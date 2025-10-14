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
    module: glu_update_device_attributes
    short_description: Update device attributes on a Gluware Device within Gluware Control
    description:
    - Updates the Gluware device with specified attribute values in Gluware Control.
    - By default, this module uses the device_id parameter to find the device in Gluware.
    - You may instead specify the device's friendly name and organization name instead of a device_id.
    - "Note: If you see 'HTTP Error 400: Bad Request', the playbook task may be trying to set a read-only or non-existent attribute."
    version_added: '2.8.0'
    author:
    - John Anderson (@gluware-inc)
    - Oleg Gratwick (@ogratwick-gluware)
    options:
        data:
            description:
                - Key/Value pairs to update for the target device.
            type: dict
            required: True
    extends_documentation_fragment:
    - gluware_inc.control.gluware_control
'''

EXAMPLES = r'''

- name: Update the custom attribute playbook_date with the current date in Gluware Control
  gluware_inc.control.glu_update_device_attributes:
    org_name: "gluware_organization"
    name: "{{inventory_hostname}}"
    gluware_control: "{{control}}"
    data:
      playbook_date: "{{ lookup('pipe','date +%Y-%m-%d-%H-%M-%S') }}"

- name: Update the device description via direct connection params
  gluware_inc.control.glu_update_device_attributes:
    org_name: "gluware_organization"
    name: "device_01"
    gluware_control:
      host: "https://1.1.1.1"
      username: "ansible_user"
      password: "ansible_password"
      trust_any_host_https_certs: true
    data:
      description: "Updated Device Description"
'''

RETURN = r'''
msg:
  description: Device facts with the updated values
  returned: success
  type: dict
'''

import os
import re
import json
import base64

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.common.text.converters import to_text, to_bytes

from ansible_collections.gluware_inc.control.plugins.module_utils.gluware_utils import GluwareAPIClient

try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


def run_module():

    module_args = GluwareAPIClient.gluware_common_params()
    module_args.update(data=dict(type='dict', required=True))

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_id', 'org_name']],
        mutually_exclusive=[['glu_device_id', 'name']],
        supports_check_mode=False
    )

    org_name = module.params.get('org_name')
    name = module.params.get('name')
    glu_device_id = module.params.get('glu_device_id') or ""
    api_data = module.params.get('data') or {}

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

    api_host = api_dict['host']
    if not re.match(r'(?:http|https)://', api_host or ''):
        api_host = 'https://{host}'.format(host=api_host)

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

    if glu_device_id:
        if name:
            module.warn("When 'glu_device_id' is specified, 'name' must not be set. Only using glu_device_id")
        glu_api = GluwareAPIClient(request_payload, api_host)
    else:
        if not org_name or not name:
            module.fail_json(msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    if not glu_device_id:
        module.fail_json(msg="No Gluware ID found for device", changed=False)

    api_url = urljoin(api_host, '/api/devices/{}'.format(glu_device_id))

    res = http_request(module, api_url, "PUT", payload=api_data, headers=base_headers)

    if res["status"] not in (200, 204):
        body_txt = res.get("body", "") or res.get("reason", "")
        if res["status"] == 400:
            body_txt = body_txt or "Invalid attribute(s) or values for the device. Data provided: {}".format(json.dumps(api_data))
        module.fail_json(
            msg="Unexpected response from Gluware Control (update device attributes): HTTP {} - {}".format(
                res["status"], body_txt
            ),
            changed=False
        )

    try:
        msg_payload = json.loads(res["body"]) if res.get("body") else {}
    except Exception:
        msg_payload = {"raw": res.get("body", "")}

    result = dict(changed=True, msg=msg_payload)
    module.exit_json(**result)


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
