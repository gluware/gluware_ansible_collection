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
module: glu_device
short_description: Manage the lifecycle of target device in Gluware Device Manager
description:
    - Updates/Creates/Deletes device in Device Manager.
    - By default this module will use glu_device_id parameter to find the device in Gluware.
    - This module supports specifying the friendly name of the device if the organization name
        is specified as well instead of supplying the glu_device_id parameter.
version_added: "2.8.0"
author:
- Oleg Gratwick (@ogratwick-gluware)
options:
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
    glu_device_id:
        description:
        - ID of the device within Gluware.
        - The glu_devices inventory plugin automatically supplies this variable.
        type: str
        required: False
    org_name:
        description:
        - Organization name the device is in within Gluware.
        type: str
        required: True
    name:
        description:
        - Target device name within Gluware Control.
        type: str
        required: False
    timeout:
        description:
        - Amount of time in seconds to wait for the execution to complete.
        type: int
        default: 60
        required: False
    state:
        description:
        - Type of action to take on target device for lifecycle management.
        - O(state=present) - Ensures the device exists in Gluware Device Manager and properties are properly configured.
        - O(state=absent) - Ensures the device does not exist in Gluare Device Manager.
        choices:
        - present
        - absent
        default: present
        type: str
    description:
        description:
        - Updates the description of the device
        required: False
        type: str
    ip:
        description:
        - IP Address of device
        required: False
        type: str
    connection_type:
        description:
        - Connection used to connect to device from Gluware Control
        - O(connection_type=ssh) - Communicate with device using Telnet using Gluware
        - O(connection_type=telnet) - Communicate with device using SSH using Gluware
        - O(connection_type=https) - Communicate with device using REST API using Gluware
        choices:
        - ssh
        - telnet
        - https
        default: ssh
        required: False
        type: str
    port:
        description:
        - Port used for the connection_type value specified
        type: int
        required: False
    credentials:
        description:
        - Vault credential that will be used by Gluware to authenticate to device
        required: False
        type: str
    enable_pass:
        description:
        - Vault credential that will be used by Gluware to elevate privileges
        required: False
        type: str
    custom_fields:
        description:
        - Custom Field key/value pairs to update for the target device.
        type: dict
        required: False
    connection_method:
        description:
        - Connection Method. Allowed values can change with loaded packages.
        - O(connection_method=cliConnection) - Communicate with device using CLI using Gluware
        - O(connection_method=cliConnectionWithRest) - Communicate with device using CLI on a API based device using Gluware
        - O(connection_method=merakiApiConnection) - Communicate with Meraki devices using API
        - O(connection_method=aciApiConnection) - Communicate with APIC using API
        type: str
        choices:
        - cliConnection
        - cliConnectionWithRest
        - merakiApiConnection
        - aciApiConnection
        required: False
        default: cliConnection
    discovery_level:
        description:
        - Device discovery level
        choices:
        - 1
        - 2
        - 3
        type: int
        required: False
        default: 3
    management_state:
        description:
        - Set management state of the device
        choices:
        - managed
        - unmanaged
        - inventory_only
        - non_inventory
        default: managed
        required: False
        type: str
    file_server_identifier:
        description:
        - Name of primary file server to use for OS management
        type: str
        required: False
    vrf:
        description:
        - Exact name of the virtual routing and forwarding interface
        required: False
        type: str
    use_issu:
        description:
        - Use non-disruptive upgrade when available for device
        type: bool
        required: False
    environment:
        description:
        - Set environment assignment for device.
        required: False
        default: production
        type: str
        choices:
        - production
        - test
        - production-test
    site_name:
        description:
        - Name of site to assign to device
        required: False
        type: str
    zone_name:
        description:
        - Name of the zone the device belongs to.  This is the name of the Zone not the Display Name. Please check the settings page for the value.
        required: False
        type: str
    lock_engine:
        description:
        - Lock zone indicator
        type: bool
        required: False
    proxy_ip:
        description:
        - IP Address of the Proxy server used to reach device from Gluware
        required: False
        type: str
    proxy_connection_type:
        description:
        - Proxy connection type used by Gluware to communicate with end device
        - O(proxy_connection_type=ssh) - Communicate with proxy using Telnet using Gluware
        - O(proxy_connection_type=telnet) - Communicate with proxy using SSH using Gluware
        choices:
        - ssh
        - telnet
        type: str
        required: False
    proxy_port:
        description:
        - Port used for the proxy_connection_type proxy value specified
        type: int
        required: False
    proxy_credentials:
        description:
        - Vault credential that will be used by Gluware to authenticate to proxy
        required: False
        type: str
'''

EXAMPLES = r'''
- name: Update Device
  gluware_inc.control.glu_device:
    org_name: "{{org_name}}"
    name: "{{inventory_hostname}}"
    gluware_control: "{{control}}"
    state: present
    management_state: "unmanaged"
    timeout: 50
    description: Ansible description
    discovery_level: 2
    use_issu: true
    environment: production-test
    site_name: NYC01
    zone_name: zoneSacramento
    vrf: test
    lock_engine: true
    custom_fields:
    PDU Port: "12"
    Console Port: "55"

- name: Create Device
  gluware_inc.control.glu_device:
    org_name: "{{org_name}}"
    name: newDevice
    gluware_control: "{{control}}"
    state: present
    management_state: inventory_only
    timeout: 30
    description: new device
    discovery_level: 3
    use_issu: false
    environment: test
    zone_name: System
    lock_engine: false
    credentials: admin
    enable_pass: enable
    connection_method: cliConnection
    vrf: test
    ip: 1.1.1.1
    port: 55
    proxy_ip: 5.5.5.5
    proxy_port: 44
    proxy_credentials: test
    file_server_identifier: REMOTE
  run_once: true

- name: Delete Device
  gluware_inc.control.glu_device:
    org_name: "{{org_name}}"
    name: newDevice
    gluware_control: "{{control}}"
    state: absent
  run_once: true
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
    # Module parameters (kept aligned with original)
    documented_args = {
        'state': dict(type='str', choices=['present', 'absent'], default='present'),
        'description': dict(type='str'),
        'ip': dict(type='str'),
        'connection_type': dict(type='str', choices=['ssh', 'telnet', 'https'], default='ssh', required=False),
        'port': dict(type='int'),
        'credentials': dict(type='str'),
        'enable_pass': dict(type='str', no_log=True),
        'org_name': dict(type='str', required=True),
        'name': dict(type='str', required=False),
        'glu_device_id': dict(type='str', required=False),
        'timeout': dict(type='int', required=False, default=60),
        'gluware_control': {
            'type': 'dict',
            'required': True,
            'options': {
                'host': {'type': 'str', 'required': False},
                'username': {'type': 'str', 'required': False},
                'password': {'type': 'str', 'required': False, 'no_log': True},
                'trust_any_host_https_certs': {'type': 'bool', 'required': False, 'default': False},
            },
        },
        'custom_fields': dict(type='dict'),
        'connection_method': dict(type='str',
                                  choices=['cliConnection', 'cliConnectionWithRest', 'merakiApiConnection', 'aciApiConnection'],
                                  default='cliConnection'),
        'discovery_level': dict(type='int', choices=[1, 2, 3], default=3),
        'management_state': dict(type='str', choices=['managed', 'unmanaged', 'inventory_only', 'non_inventory'], default='managed'),
        'file_server_identifier': dict(type='str'),
        'vrf': dict(type='str'),
        'use_issu': dict(type='bool'),
        'environment': dict(type='str', choices=['production', 'test', 'production-test'], default='production'),
        'site_name': dict(type='str'),
        'zone_name': dict(type='str'),
        'lock_engine': dict(type='bool'),
        'proxy_ip': dict(type='str'),
        'proxy_connection_type': dict(type='str', choices=['ssh', 'telnet']),
        'proxy_port': dict(type='int'),
        'proxy_credentials': dict(type='str')
    }
    module = AnsibleModule(
        argument_spec=documented_args,
        supports_check_mode=False
    )

    params = module.params
    org_name = params.get('org_name')
    name = params.get('name')
    glu_device_id = params.get('glu_device_id') or ""

    # Connection info from params or env
    user_params = params.get('gluware_control') or {}
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
    if not re.match(r'(?:http|https)://', api_host):
        api_host = 'https://{host}'.format(host=api_host)

    # Certs/proxy settings (fetch_url reads these from module.params)
    validate_certs = not _to_bool(api_dict['trust_any_host_https_certs'])
    module.params['validate_certs'] = validate_certs

    # Base headers including Basic auth
    base_headers = {'Content-Type': 'application/json'}
    base_headers.update(_basic_auth_header(api_dict['username'], api_dict['password']))

    api_url = urljoin(api_host, '/api/devices')

    # If user supplied both glu_device_id and name, prefer glu_device_id but warn
    if glu_device_id and name:
        try:
            module.warn("When 'glu_device_id' is specified, 'name' is ignored; only using 'glu_device_id'.")
        except AttributeError:
            pass  # older Ansible might not have module.warn

    # If we don't have a device id, we need to look it up by org/name
    if not glu_device_id:
        if not org_name or not name:
            module.fail_json(msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        request_payload = {
            # Use username/password fields as requested; no url_username/url_password
            "username": api_dict['username'],
            "password": api_dict['password'],
            "validate_certs": validate_certs,
            "force_basic_auth": True,
            "headers": base_headers
        }
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device(name, org_name)
        glu_device_id = (glu_device or {}).get('id')

    state = params.get('state')
    OK_STATUSES = (200, 201, 202, 204)
    if state == "present":
        if not org_name:
            module.fail_json(msg="'org_name' is required.", changed=False)
        data = check_dev(params)  # dev isn't used; keep signature
        if glu_device_id:
            update_url = api_url.rstrip('/') + '/' + glu_device_id
            result = http_request(module, update_url, "PUT", payload=data, headers=base_headers)
            status = result["status"]
            if status not in OK_STATUSES:
                message = json.loads(result["info"]["body"].decode("utf-8"))
                module.fail_json(
                    msg="Unexpected response from Gluware Control: HTTP {} - {}".format(status, message),
                    changed=False
                )
            module.exit_json(changed=True)
        else:
            glu_org = glu_api._get_org_name(org_name)
            if not glu_org:
                module.fail_json(msg="No organization found with name {}".format(org_name))
            data["orgId"] = glu_org[0].get('id')
            result = http_request(module, api_url, "POST", payload=data, headers=base_headers)
            status = result["status"]
            if status not in OK_STATUSES:
                message = json.loads(result["info"]["body"].decode("utf-8"))
                module.fail_json(
                    msg="Unexpected response from Gluware Control: HTTP {} - {}".format(status, message),
                    changed=False
                )
            module.exit_json(changed=True)

    elif state == "absent":
        update_url = api_url.rstrip('/') + '/' + glu_device_id
        result = http_request(module, update_url, "DELETE", headers=base_headers)
        status = result["status"]
        if status not in OK_STATUSES:
            message = json.loads(result["info"]["body"].decode("utf-8"))
            module.fail_json(
                msg="Unexpected response from Gluware Control: HTTP {} - {}".format(status, message),
                changed=False
            )
        module.exit_json(changed=True)
    else:
        module.fail_json(msg="'state' parameter must be one of: present, absent.")


def check_dev(params):
    proxy_check = params.get("proxy_ip")
    if proxy_check is not None and proxy_check != 'None' and proxy_check != "":
        data = {
            "connectionInformation": {
                "proxyList": [{}]
            }
        }
    else:
        data = {
            "connectionInformation": {}
        }
    for key, value in params.items():
        if value is not None and value != 'None' and value != "":
            if key == "management_state":
                data["managementState"] = value.upper()
            elif key == "discovery_level":
                data["discoveryLevel"] = value
            elif key == "name":
                data["name"] = value
            elif key == "file_server_identifier":
                data["fileServerIdentifier"] = value
            elif key == "site_name":
                data["siteName"] = value
            elif key == "zone_name":
                data["zoneName"] = value
            elif key == "lock_engine":
                data["lockEngine"] = value
            elif key == "connection_method":
                data["connectionMethod"] = value
            elif key == "vrf":
                data["vrf"] = value
            elif key == "use_issu":
                data["useIssu"] = value
            elif key == "environment":
                data["environment"] = value.upper()
            elif key == "state":
                continue
            elif key == "description":
                data["description"] = value
            elif key == "ip":
                data["connectionInformation"]["ip"] = value
            elif key == "connection_type":
                data["connectionInformation"]["type"] = value
            elif key == "port":
                data["connectionInformation"]["port"] = value
            elif key == "credentials":
                value = "{{credentials.$}}".replace("$", value, 1)
                data["connectionInformation"]["credentials"] = value
            elif key == "enable_pass":
                value = "{{credentials.$}}".replace("$", value, 1)
                data["connectionInformation"]["enablePassword"] = value
            elif key == "org_name":
                continue
            elif key == "proxy_ip":
                data["connectionInformation"]["proxyList"][0]["ip"] = value
            elif key == "proxy_connection_type":
                data["connectionInformation"]["proxyList"][0]["type"] = value
            elif key == "proxy_port":
                data["connectionInformation"]["proxyList"][0]["port"] = value
            elif key == "proxy_credentials":
                value = "{{credentials.$}}".replace("$", value, 1)
                data["connectionInformation"]["proxyList"][0]["credentials"] = value
            elif key == "custom_fields":
                # merge user-provided custom fields at top-level
                if isinstance(value, dict):
                    data.update(value)
    return data


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
