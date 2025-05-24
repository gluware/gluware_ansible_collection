#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
# GNU General Public License v3.0+
# This file is part of Ansible
# (c) 2020, Gluware Inc.
# Licensed under the GNU General Public License version 3 as published by
# the Free Software Foundation.
# See https://www.gnu.org/licenses/gpl-3.0.txt

from ansible_collections.gluware_inc.control.plugins.module_utils.gluware_utils import GluwareAPIClient
import os
import json
import re
import urllib.error as urllib_error
import http.client as httplib
import socket
from ansible.module_utils.urls import Request
from ansible.module_utils.basic import AnsibleModule
ANSIBLE_METADATA = {'metadata_version': '1.1.0',
                    'status': ['stableinterface'],
                    'supported_by': 'Gluware Inc'}

DOCUMENTATION = '''
    module: glu_audit_config
    short_description: Perform a audit on the current captured config on a Gluware Device
    description:
    - For the current Gluware device trigger a audit on the current captured config in Gluware Control.
    - By default this module will use device_id parameter to find the device in Gluware.
    - This module supports specifying the friendly name of the device if the organization name is specified as well instead of supplying the device_id parameter.  
    version_added: '2.8'
    author:
    - John Anderson (@gluware-inc)
    - Oleg Gratwick (@ogratwick-gluware)
    options:
        description:
            description:
            - Description for the instance of this audit execution.
            type: str
            required: True
        audit_policy:
            description:
            - Audit Policy Name as displayed in Gluware Config Drift & Audit.
            type: str
            required: True
    extends_documentation_fragment:
    - gluware_inc.control.gluware_control
'''

EXAMPLES = r'''
    #
    # Trigger a Gluware Control audit on the current captured config for the current device.
    #
- name: Creating a audit on the current captured config for the current device
    glu_audit_config:
    gluware_control: "{{control}}"
    glu_device_id: "{{ glu_device_id }}"
    description: "Checking config for correct NTP Server"
    audit_policy: "Data Center NTP Server Audit"

'''

try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin


def run_module():
    module_args = GluwareAPIClient.gluware_common_params()
    # Module parameters
    module_args.update(dict(
        description=dict(type='str', required=True),
        audit_policy=dict(type='str', required=True),
    ))

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_id', 'org_name']],
        mutually_exclusive=[['glu_device_id', 'org_name']],
        supports_check_mode=False
    )
    org_name = module.params.get('org_name')
    name = module.params.get('name')
    audit_policy = module.params.get('audit_policy')
    description = module.params.get('description')

    if module.params.get('glu_device_id'):
        glu_device_id = module.params.get('glu_device_id')
    else:
        glu_device_id = ""
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
    if not re.match('(?:http|https)://', api_host):
        api_host = 'https://{host}'.format(host=api_host)

    http_headers = {
        'Content-Type': 'application/json'
    }

    request_handler = Request(
        url_username=api_dict['username'],
        url_password=api_dict['password'],
        validate_certs=not api_dict['trust_any_host_https_certs'],
        force_basic_auth=True,
        headers=http_headers
    )
    # Default result JSON object

    request_payload = {
        "url_username": api_dict['username'],
        "url_password": api_dict['password'],
        "validate_certs": not api_dict['trust_any_host_https_certs'],
        "force_basic_auth": True,
        "headers": http_headers
    }
    if glu_device_id:
        # Only glu_device_id should be used
        if org_name or name:
            module.warning_json(
                msg="When 'glu_device_id' is specified, 'org_name' and 'name' must not be set. Only using glu_device_id")
    else:
        # org_name and name must both be provided
        if not org_name or not name:
            module.fail_json(
                msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    glu_api = GluwareAPIClient(request_payload, api_host)
    glu_org_id = glu_api._get_org_name(org_name)
    if not glu_org_id:
        module.fail_json(msg="No organization found with name {}".format(org_name))
    org_id = glu_org_id[0].get('id')
    # This api call is for Gluware Control.
    api_url_1 = urljoin(api_host, '/api/audit/policies?orgId=' + org_id)

    try:
        response = request_handler.get(api_url_1)
    except (ConnectionError, httplib.HTTPException, socket.error, urllib_error.URLError) as e2:
        error_msg = 'Gluware Control call failed for getting audit policy: {msg}'.format(
            msg=e2)
        module.fail_json(msg=error_msg, changed=False)

    # Read in the JSON response to a object.
    array_response = []
    try:
        read_response = response.read()
        array_response = json.loads(read_response)
        for resp in array_response:
            if resp.get('name') == audit_policy:
                audit_policy_id = resp.get('id')
    except (ValueError, TypeError) as e:
        error_msg = 'Gluware Control call getting audit policy response failed to be parsed ' \
        'as JSON: {msg}'.format(
            msg=e)
        module.fail_json(msg=error_msg, changed=False)

    if len(array_response) == 0:
        error_msg = 'No audit policy was found for the name: "{msg}"'.format(
            msg=audit_policy)
        module.fail_json(msg=error_msg, changed=False)

    if not audit_policy_id:
        error_msg = 'No audit policy id was found for the name: "{msg}"'.format(
            msg=audit_policy)
        module.fail_json(msg=error_msg, changed=False)

    # This api call is for Gluware Control.
    api_url_2 = urljoin(api_host, '/api/audit/execute')

    # Create the body of the request.
    api_data = {
        "name": description,
        "deviceIds": [glu_device_id],
        "policyId": audit_policy_id,
        "capture": False
    }
    http_body = json.dumps(api_data)

    # Make the actual api call.
    try:
        response = request_handler.post(api_url_2, data=http_body)
    except (ConnectionError, httplib.HTTPException, socket.error, urllib_error.URLError) as e2:
        error_msg = 'Gluware Control call failed for executing the audit: {msg}'.format(
            msg=e2)
        module.fail_json(msg=error_msg, changed=False)

    if response.status != 204:
        error_msg = f"Unexpected response from Gluware Control: HTTP {response.status} - {response.reason}"
        module.fail_json(msg=error_msg, changed=False)
    result = dict(changed=True)
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
