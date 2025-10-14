#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
# GNU General Public License v3.0+
# This file is part of Ansible
# (c) 2020, Gluware Inc.
# Licensed under the GNU General Public License version 3 as published by
# the Free Software Foundation.
# See https://www.gnu.org/licenses/gpl-3.0.txt

ANSIBLE_METADATA = {'metadata_version': '1.1.0',
                    'status': ['stableinterface'],
                    'supported_by': 'Gluware Inc'}

DOCUMENTATION = '''
  module: glu_rpa_workflow_batch
  short_description: Run a single RPA workflow execution across multiple Gluware Devices
  description:
    - Triggers an RPA workflow in Gluware Control for multiple devices in one execution.
    - Provide C(glu_device_ids), or provide C(glu_device_names) together with C(org_name).
  version_added: '2.9.0'
  author:
    - Oleg Gratwick (@ogratwick-gluware)
  options:
    input_parameters:
        description:
        - RPA workflow parameters to be supplied during execution of the workflow.
        - The Org ID is not required to be supplied.
        type: dict
        required: False
    workflow_name:
        description:
        - Display name of the workflow
        type: str
        required: True
    gluware_control:
      description:
        - Connection details for the Gluware Control platform.
      type: dict
      required: True
      suboptions:
        host:
          description: Hostname or IP address of the Gluware Control server.
          type: str
        username:
          description: Username for authentication with Gluware Control.
          type: str
        password:
          description: Password for authentication with Gluware Control.
          type: str
        trust_any_host_https_certs:
          description: Bypass HTTPS certificate verification.
          type: bool
          default: False
    org_name:
      description:
        - Organization name the devices are in within Gluware.
        - Required when using C(glu_device_names).
      type: str
      required: False
    glu_device_ids:
      description:
        - List of device IDs within Gluware Control.
        - The C(glu_devices) inventory plugin may supply this automatically.
      type: list
      elements: str
      required: False
    glu_device_names:
      description:
        - Target device names within Gluware Control.
        - Must be used with C(org_name).
      type: list
      elements: str
      required: False
    timeout:
      description:
        - Amount of time in seconds to wait for the execution to complete.
      type: int
      default: 60
      required: False
'''

EXAMPLES = r'''
- name: Collect all device names from hosts in this play
  run_once: true
  delegate_to: localhost
  set_fact:
    all_device_names: >-
      {{ ansible_play_hosts
         | map('extract', hostvars, 'glu_name')
         | select('defined')
         | list }}

- name: Execute RPA Workflow
  gluware_inc.control.glu_rpa_workflow_batch:
    org_name: "{{ org_name }}"
    gluware_control: "{{ control }}"
    input_parameter:
      param_one: param
    glu_device_names: "{{ all_device_names }}"
    workflow_name: "Example Workflow"
    run_once: true
'''

RETURN = r'''
msg:
  description: Gluware audit rule output summary
  returned: always
  type: dict
'''

import os
import re
import json
import base64

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.common.text.converters import to_text, to_bytes

try:
    from urllib.parse import urljoin, urlencode
except ImportError:
    from urlparse import urljoin
    from urllib import urlencode

from ansible_collections.gluware_inc.control.plugins.module_utils.gluware_utils import GluwareAPIClient


def run_module():
    module_args = dict(
        gluware_control=dict(
            type='dict',
            required=True,
            options=dict(
                host=dict(type='str', required=False),
                username=dict(type='str', required=False),
                password=dict(type='str', required=False, no_log=True),
                trust_any_host_https_certs=dict(type='bool', required=False, default=False),
            ),
        ),
        org_name=dict(type='str', required=False),
        glu_device_ids=dict(type='list', elements='str', required=False),
        glu_device_names=dict(type='list', elements='str', required=False),
        workflow_name=dict(type='str', required=True),
        input_parameters=dict(type='dict', required=False),
        timeout=dict(type='int', required=False, default=60)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_ids', 'glu_device_names']],
        mutually_exclusive=[['glu_device_ids', 'glu_device_names']],
        supports_check_mode=False
    )

    timeout = module.params.get('timeout') or 60
    org_name = module.params.get('org_name')
    device_names = module.params.get('glu_device_names')
    input_parameters = module.params.get('input_parameters')
    workflow_name = module.params.get('workflow_name')

    # Resolve devices to IDs
    if module.params.get('glu_device_ids'):
        glu_device_ids = module.params.get('glu_device_ids')
        if device_names:
            module.warn("When 'glu_device_ids' is specified, 'glu_device_names' will be ignored.")
    else:
        glu_device_ids = []
        if not org_name or not device_names:
            module.fail_json(msg="Both 'org_name' and 'glu_device_names' are required when 'glu_device_ids' is not provided.")

    # Gather connection info from parameters or environment
    user_params = module.params.get('gluware_control') or {}
    api_dict = {
        'host': user_params.get('host') or os.environ.get('GLU_CONTROL_HOST'),
        'username': user_params.get('username') or os.environ.get('GLU_CONTROL_USERNAME'),
        'password': user_params.get('password') or os.environ.get('GLU_CONTROL_PASSWORD'),
        'trust_any_host_https_certs': user_params.get('trust_any_host_https_certs') or os.environ.get('GLU_CONTROL_TRUST_ANY_HOST_HTTPS_CERTS'),
    }

    for key in ['host', 'username', 'password']:
        if not api_dict[key]:
            module.fail_json(msg="Missing required connection parameter: {}".format(key), changed=False)

    # Ensure scheme on host
    api_host = api_dict['host']
    if not re.match(r'(?:http|https)://', api_host or ''):
        api_host = 'https://{host}'.format(host=api_host)

    # Build headers and validate_certs consistent with fetch_url usage
    validate_certs = not _to_bool(api_dict['trust_any_host_https_certs'])
    module.params['validate_certs'] = validate_certs
    base_headers = {'Content-Type': 'application/json'}
    base_headers.update(_basic_auth_header(api_dict['username'], api_dict['password']))
    OK_STATUSES = (200, 201, 202, 204)
    request_payload = {
        "url_username": api_dict['username'],
        "url_password": api_dict['password'],
        "validate_certs": validate_certs,
        "force_basic_auth": True,
        "headers": base_headers
    }

    glu_api = GluwareAPIClient(request_payload, api_host)

    if not glu_device_ids:
        glu_device_ids = glu_api._get_device_ids(device_names, org_name)

    # Resolve org id
    glu_org_list = glu_api._get_org_name(org_name)
    if not glu_org_list:
        module.fail_json(msg="No organization found with name {}".format(org_name))
    org_id = glu_org_list[0].get('id')
    api_url = urljoin(api_host, '/api/workflows')
    params = {"orgId": org_id, "name": workflow_name}
    query = urlencode(params)

    workflow_url = api_url + ("?" + query if query else "")
    glu_workflow = http_request(module, workflow_url, "GET", headers=base_headers)
    workflow_info = json.loads(glu_workflow["body"])

    if workflow_info and isinstance(workflow_info, list) and len(workflow_info) > 0:
        if "name" in workflow_info[0] and workflow_info[0]["name"]:
            workflow_id = workflow_info[0]["id"]
            url_path = "/" + workflow_id + "/run"
            update_url = api_url + url_path
            data = {
                "orgId": org_id,
                "deviceIds": glu_device_ids
            }
            if input_parameters:
                data["inputParameters"] = input_parameters

            result = http_request(module, update_url, "POST", headers=base_headers, payload=data)
            status = result["status"]
            if status not in OK_STATUSES:
                message = json.loads(result["info"]["body"].decode("utf-8"))
                module.fail_json(
                    msg="Unexpected response from Gluware Control: HTTP {} - {}".format(status, message),
                    changed=False
                )
            workflow_info = json.loads(result["body"])
            rpa_workflow = glu_api._get_rpa_status(workflow_info, timeout)
            if rpa_workflow["status"] == "COMPLETED":
                result = dict(changed=True, msg=rpa_workflow)
                module.exit_json(**result)
            else:
                module.fail_json(
                    msg="RPA Workflow {} has failed. Please check the Gluware logs.".format(workflow_name),
                    changed=False
                )
        else:
            module.fail_json(msg="Unable to find specified workflow {} in the given organization {}".format(workflow_name, org_name))

    else:
        module.fail_json(msg="Unable to find specified workflow {} in the given organization {}".format(workflow_name, org_name))


def _to_bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _basic_auth_header(username, password):
    token = base64.b64encode(("%s:%s" % (username, password)).encode("utf-8")).decode("ascii")
    return {"Authorization": "Basic " + token}


def http_request(module, url, method, payload=None, headers=None):
    """
    Wrapper around Ansible's fetch_url that never raises for HTTP errors.
    Returns a dict: status/reason/body/response/info.
    """
    hdrs = dict(headers or {})
    data = None
    if payload is not None:
        if isinstance(payload, (bytes, bytearray)):
            data = payload
        else:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    resp, info = fetch_url(
        module,
        url,
        data=data,
        headers=hdrs,
        method=method,
        use_proxy=module.params.get("use_proxy", True),
        timeout=module.params.get("timeout") or 60,
    )

    status = info.get("status")
    reason = info.get("msg", "")

    if resp is not None:
        try:
            body_bytes = resp.read()
        except Exception:
            body_bytes = to_bytes(info.get("body", "") or "")
    else:
        body_bytes = to_bytes(info.get("body", "") or info.get("exception", "") or info.get("msg", "") or "")
    body = to_text(body_bytes, errors="ignore")

    return {
        "status": status,
        "reason": reason,
        "body": body,
        "response": resp,
        "info": info,
    }


def main():
    run_module()


if __name__ == '__main__':
    main()
