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
    module: glu_restore
    short_description: Perform a device restore from backup for supported platforms in Gluware
    description:
    - For the current Gluware device trigger a restore of a backup in Gluware Control.
    - By default this module will use device_id parameter to find the device in Gluware.
    - This module supports specifying the friendly name of the device if the organization name
      is specified as well instead of supplying the device_id parameter.
    version_added: '2.8.0'
    author:
    - Oleg Gratwick (@ogratwick-gluware)
    options:
        backup_id:
            description:
            - Backup ID to restore device to.
            type: str
            required: True
    extends_documentation_fragment:
    - gluware_inc.control.gluware_control
'''

EXAMPLES = r'''
#
# Trigger a Gluware Control restore for the current device
#
- name: Restore device from Backup
  gluware_inc.control.glu_restore:
    gluware_control: "{{control}}"
    backup_id: "4c0731a2-555e-4747-9a3b-9a8ec622cf9a"
    name: "{{inventory_hostname}}"
'''

RETURN = r'''
msg:
  description: Gluware restore output summary
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

    # Module parameters
    module_args = GluwareAPIClient.gluware_common_params()
    module_args.update(backup_id=dict(type='str', required=True),)

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_id', 'org_name']],
        mutually_exclusive=[['glu_device_id', 'name']],
        supports_check_mode=False
    )

    timeout = module.params.get('timeout') or 60
    org_name = module.params.get('org_name')
    backup_id = module.params.get('backup_id')
    name = module.params.get('name')
    glu_device_id = module.params.get('glu_device_id') or ""

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
            module.fail_json(
                msg="Missing required connection parameter: {}".format(key), changed=False)

    # Ensure scheme on host
    api_host = api_dict['host']
    if not re.match(r'(?:http|https)://', api_host or ''):
        api_host = 'https://{host}'.format(host=api_host)

    # Build headers and validate_certs consistent with fetch_url usage
    validate_certs = not _to_bool(api_dict['trust_any_host_https_certs'])
    module.params['validate_certs'] = validate_certs  # let fetch_url pick it up

    base_headers = {'Content-Type': 'application/json'}
    base_headers.update(_basic_auth_header(api_dict['username'], api_dict['password']))

    request_payload = {
        "url_username": api_dict['username'],
        "url_password": api_dict['password'],
        "validate_certs": validate_certs,
        "force_basic_auth": True,
        "headers": base_headers
    }

    # Resolve device id if needed
    if glu_device_id:
        if name:
            module.warn("When 'glu_device_id' is specified, 'name' must not be set. Only using glu_device_id")
    else:
        if not org_name or not name:
            module.fail_json(
                msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        glu_api_lookup = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api_lookup._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    if not glu_device_id:
        module.fail_json(msg="No Gluware ID found for device", changed=False)

    # Create API client (used for work polling/output)
    glu_api = GluwareAPIClient(request_payload, api_host)

    # Build API URL and payload
    api_url = urljoin(api_host, '/api/devices/restore')
    api_data = {
        "deviceId": glu_device_id,
        "backupId": backup_id,
        "trackProgress": "true"
    }

    result = http_request(module, api_url, "POST", payload=api_data, headers=base_headers)
    status = result["status"]

    OK_STATUSES = (200, 201, 202, 204)
    if status not in OK_STATUSES:
        body_txt = result.get("body", "") or result.get("info", {}).get("body", "")
        try:
            body_json = json.loads(body_txt) if body_txt else {}
        except Exception:
            body_json = {}

        api_msg = (
            body_json.get("error", {}).get("message")
            or body_json.get("message")
            or result.get("reason", "Unexpected error")
        )

        module.fail_json(
            msg=api_msg,
            changed=False,
            status=status,
            details=result.get("info", {})
        )

    # Parse work id (accept dict or list payloads)
    try:
        work_payload = json.loads(result["body"] or "{}")
    except Exception:
        module.fail_json(msg="Unable to parse Gluware Control response body", changed=False)

    if isinstance(work_payload, list) and work_payload:
        work_id = work_payload[0].get("workId")
        work_json = work_payload[0]
    elif isinstance(work_payload, dict):
        work_id = work_payload.get("workId")
        work_json = work_payload
    else:
        work_id = None
        work_json = {}

    if not work_id:
        module.fail_json(msg="Gluware Control did not return a workId", changed=False)

    # Poll for completion and fetch output
    work_state = glu_api._get_work_status(work_id, timeout)

    if work_state == "SUCCESSFUL":
        job = glu_api._get_work_output(work_id, "restore")
        merged = {}
        merged.update(work_json)
        merged.update(job)
        result = dict(changed=True, msg=merged)
        module.exit_json(**result)
    else:
        module.fail_json(msg="Restore work did not complete successfully (state: {})".format(work_state), changed=False)


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
