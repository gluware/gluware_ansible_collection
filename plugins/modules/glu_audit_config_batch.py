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
  module: glu_audit_config_batch
  short_description: Run a single audit device configuration execution on multiple Gluware devices
  description:
    - Triggers an audit on the current captured config in Gluware Control for multiple devices in one execution.
    - If able to execute audit on any of the devices specified will return as successful.
    - Provide C(glu_device_ids), or provide C(glu_device_names) together with C(org_name).
  version_added: '2.9.0'
  author:
    - Oleg Gratwick (@ogratwick-gluware)
  options:
    description:
      description:
        - Execution title of the audit.
      type: str
      required: True
    audit_policy:
      description:
        - Audit policy name as displayed in Gluware Config Drift & Audit application.
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

- name: Trigger ONE Gluware audit for ALL devices
  run_once: true
  delegate_to: localhost
  gluware_inc.control.glu_audit_config_batch:
    org_name: "{{ org_name }}"
    gluware_control: "{{ control }}"
    description: "{{ description }}"
    audit_policy: "{{ audit_policy }}"
    glu_device_names: "{{ all_device_names }}"
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
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

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
        description=dict(type='str', required=True),
        audit_policy=dict(type='str', required=True),
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
    audit_policy = module.params.get('audit_policy')
    description = module.params.get('description')

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

    request_payload = {
        "url_username": api_dict['username'],
        "url_password": api_dict['password'],
        "validate_certs": validate_certs,
        "force_basic_auth": True,
        "headers": base_headers
    }

    # Gluware client (used for name/ID resolution + work poll/output)
    glu_api = GluwareAPIClient(request_payload, api_host)

    # Resolve names -> ids if needed
    if not glu_device_ids:
        glu_device_ids = glu_api._get_device_ids(device_names, org_name)

    # Resolve org id
    glu_org_list = glu_api._get_org_name(org_name)
    if not glu_org_list:
        module.fail_json(msg="No organization found with name {}".format(org_name))
    org_id = glu_org_list[0].get('id')

    # Find policy id
    api_url_policies = urljoin(api_host, '/api/audit/policies?orgId=' + org_id)
    result = http_request(module, api_url_policies, "GET", headers=base_headers)
    if result["status"] not in (200, 204):
        module.fail_json(
            msg="Unexpected response from Gluware Control (policies): HTTP {} - {}".format(
                result["status"], result.get("reason", "")
            ),
            changed=False
        )

    audit_policy_id = None
    try:
        payload = json.loads(result["body"] or "[]")
        for resp in payload or []:
            if resp.get('name') == audit_policy:
                audit_policy_id = resp.get('id')
                break
    except (ValueError, TypeError) as e:
        module.fail_json(msg='Gluware Control policies response failed to parse as JSON: {}'.format(e), changed=False)

    if not audit_policy_id:
        module.fail_json(msg='No audit policy id was found for the name: "{}"'.format(audit_policy), changed=False)

    api_url_execute = urljoin(api_host, '/api/audit/execute')
    api_data = {
        "name": description,
        "deviceIds": glu_device_ids,
        "policyId": audit_policy_id,
        "capture": False,
        "trackProgress": "true"
    }

    exec_res = http_request(module, api_url_execute, "POST", payload=api_data, headers=base_headers)
    if exec_res["status"] not in (200, 201, 202, 204):
        body_txt = exec_res.get("body", "") or exec_res.get("reason", "")
        module.fail_json(
            msg="Unexpected response from Gluware Control (execute): HTTP {} - {}".format(exec_res["status"], body_txt),
            changed=False
        )

    try:
        work_json = json.loads(exec_res["body"] or "{}")
    except Exception:
        module.fail_json(msg="Unable to parse Gluware Control execute response body", changed=False)

    work_id = work_json.get("workId")
    if not work_id:
        module.fail_json(msg="Gluware Control did not return a workId", changed=False)

    # Poll for completion
    work_state = glu_api._get_work_status(work_id, timeout)

    if work_state == "SUCCESSFUL":
        job = glu_api._get_work_output(work_id, "audit")
        merged = {}
        if job["deviceSuccessCount"] > 0:
            merged.update(work_json)
            merged.update(job)
            result = dict(changed=True, msg=merged)
            module.exit_json(**result)
        else:
            module.fail_json(msg="Audit work did not complete successfully (state: {})".format(work_state), changed=False)
    else:
        module.fail_json(msg="Audit work did not complete successfully (state: {})".format(work_state), changed=False)


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
