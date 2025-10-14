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
    module: glu_rpa_workflow
    short_description: Execute Gluware RPA Worfklow
    description:
    - Execute a RPA workflow created in Gluware. Each device will execute a separate workflow instance.
    - By default this module will use device_id parameter to find the device in Gluware.
    - This module supports specifying the friendly name of the device if the organization name
      is specified as well instead of supplying the device_id parameter.
    version_added: '2.8.0'
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
    extends_documentation_fragment:
    - gluware_inc.control.gluware_control
'''

EXAMPLES = r'''
#
# Trigger a Gluware Control config capture for the current device
#
- name: Execute RPA Workflow
  gluware_inc.control.glu_rpa_workflow:
    gluware_control: "{{control}}"
    input_parameter:
      param_one: param
    device_id: "{{ glu_device_id }}"
    workflow_name: "Example Workflow"
'''

RETURN = r'''
msg:
  description: Gluware snapshot output summary
  returned: always
  type: dict
'''

import os
import json
import re
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.common.text.converters import to_text, to_bytes

from ansible_collections.gluware_inc.control.plugins.module_utils.gluware_utils import GluwareAPIClient

try:
    from urllib.parse import urljoin, urlencode
except ImportError:
    from urlparse import urljoin
    from urllib import urlencode


def run_module():
    module_args = GluwareAPIClient.gluware_common_params()
    module_args.update(dict(
        workflow_name=dict(type='str', required=True),
        input_parameters=dict(type='dict', required=False)
    ))

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_id', 'org_name']],
        mutually_exclusive=[['glu_device_id', 'name']],
        supports_check_mode=False
    )
    timeout = module.params.get('timeout') or 60
    update_url = None
    url_path = None
    org_name = module.params.get('org_name')
    name = module.params.get('name')
    workflow_name = module.params.get('workflow_name')
    if module.params.get('glu_device_id'):
        glu_device_id = module.params.get('glu_device_id')
    else:
        glu_device_id = ""
    # Gather connection info from parameters or environment

    user_params = module.params.get('gluware_control') or {}
    input_parameters = module.params.get('input_parameters')
    api_dict = {
        'host': user_params.get('host') or os.environ.get('GLU_CONTROL_HOST'),
        'username': user_params.get('username') or os.environ.get('GLU_CONTROL_USERNAME'),
        'password': user_params.get('password') or os.environ.get('GLU_CONTROL_PASSWORD'),
        'trust_any_host_https_certs': user_params.get('trust_any_host_https_certs') or os.environ.get('GLU_CONTROL_TRUST_ANY_HOST_HTTPS_CERTS'),
    }

    for key in ['host', 'username', 'password']:
        if not api_dict[key]:
            module.fail_json(
                msg="Missing required connection parameter: {}".format(key), changed=False)

    validate_certs = not _to_bool(api_dict['trust_any_host_https_certs'])
    module.params['validate_certs'] = validate_certs
    api_host = api_dict.get('host')

    api_host = api_dict['host']
    if not re.match('(?:http|https)://', api_host):
        api_host = 'https://{host}'.format(host=api_host)

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
    if glu_device_id:
        if name:
            module.warning_json(
                msg="When 'glu_device_id' is specified, 'name' must not be set. Only using glu_device_id")
    else:
        if not org_name or not name:
            module.fail_json(
                msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    if not glu_device_id:
        module.fail_json(msg="No Gluware ID found for device", changed=False)

    glu_api = GluwareAPIClient(request_payload, api_host)
    glu_org_id = glu_api._get_org_name(org_name)
    org_id = glu_org_id[0].get('id')

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

        else:
            module.fail_json(msg="Unable to find specified workflow {} in the given organization {}".format(workflow_name, org_name))

    else:
        module.fail_json(msg="Unable to find specified workflow {} in the given organization {}".format(workflow_name, org_name))

    data = {
        "orgId": org_id,
        "deviceIds": [glu_device_id]
    }
    if input_parameters:
        data["inputParameters"] = input_parameters
    update_url = api_url + url_path
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
    Auth is provided via Authorization header; no url_username/url_password.
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

    # Use only broadly-supported kwargs; validate_certs is picked from module.params
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
    # Prefer real body stream if available
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
