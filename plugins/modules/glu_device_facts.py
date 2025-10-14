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
    module: glu_device_facts
    short_description: View the facts of device in Gluware
    description:
    - For the current Gluware device view the discovered facts.
    - By default this module will use device_id parameter to find the device in Gluware.
    - This module supports specifying the friendly name of the device if the organization name
      is specified as well instead of supplying the device_id parameter.
    version_added: '2.8.0'
    author:
    - Oleg Gratwick (@ogratwick-gluware)
    extends_documentation_fragment:
    - gluware_inc.control.gluware_control
'''

EXAMPLES = r'''
#
# Trigger a Gluware Control config capture for the current device
#
- name: View Device Facts
  gluware_inc.control.glu_device_facts:
    gluware_control: "{{control}}"
    device_id: "{{ glu_device_id }}"
'''

RETURN = r'''
msg:
  description: Gluware device facts
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
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin


def run_module():

    module_args = GluwareAPIClient.gluware_common_params()
    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_id', 'org_name']],
        mutually_exclusive=[['glu_device_id', 'name']],
        supports_check_mode=True
    )
    timeout = module.params.get('timeout') or 60
    org_name = module.params.get('org_name')
    description = module.params.get('description')
    name = module.params.get('name')
    if module.params.get('glu_device_id'):
        glu_device_id = module.params.get('glu_device_id')
    else:
        glu_device_id = ""

    user_params = module.params.get('gluware_control') or {}

    # Figure out the Gluware Control connection information.
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

    # Make sure there is a http or https preference for the api_host
    api_host = api_dict['host']
    if not re.match('(?:http|https)://', api_host):
        api_host = 'https://{host}'.format(host=api_host)

    base_headers = {'Content-Type': 'application/json'}
    base_headers.update(_basic_auth_header(api_dict['username'], api_dict['password']))
    OK_STATUSES = (200, 201, 202, 204)
    get_device = True

    if glu_device_id:
        # Only glu_device_id should be used
        if name:
            module.warning_json(
                msg="When 'glu_device_id' is specified, 'name' must not be set. Only using glu_device_id")
    else:
        # org_name and name must both be provided
        if not org_name or not name:
            module.fail_json(
                msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        request_payload = {
            "url_username": api_dict['username'],
            "url_password": api_dict['password'],
            "validate_certs": validate_certs,
            "force_basic_auth": True,
            "headers": base_headers
        }
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    if not glu_device_id:
        module.fail_json(msg="No Gluware ID found for device", changed=False)

    api_url = urljoin(api_host, '/api/devices/')

    update_url = api_url.rstrip('/') + '/' + glu_device_id
    result = http_request(module, update_url, "GET", headers=base_headers)
    status = result["status"]
    if status not in OK_STATUSES:
        message = json.loads(result["info"]["body"].decode("utf-8"))
        module.fail_json(
            msg="Unexpected response from Gluware Control: HTTP {} - {}".format(status, message),
            changed=False
        )
    module.exit_json(changed=False, msg=json.loads(result["body"]))


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
