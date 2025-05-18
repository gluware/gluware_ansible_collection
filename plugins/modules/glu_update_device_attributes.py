#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Gluware Inc.

ANSIBLE_METADATA = {'metadata_version': '1.1.0',
                    'status': ['stableinterface'],
                    'supported_by': 'Gluware Inc'}

DOCUMENTATION = '''
    module: glu_update_device_attributes
    short_description: Update device attributes on a Gluware Device within Gluware Control
    description:
        - Updates the Gluware device with a specified attribute values in Gluware Control.  
        - By default this module will use device_id parameter to find the device in Gluware.
        - This module supports specifying the friendly name of the device if the organization name is specified as well instead of supplying the device_id parameter.  
        Note: If an error of 'HTTP Error 400: Bad Request' is displayed then possibly the playbook task is trying to set a
        read only attribute or a non existent attribute.
    version_added: '2.8'
    author:
        - John Anderson
        - Oleg Gratwick
    options:
        gluware_control:
            description:
                - Connection details for the Gluware Control platform.
            type: dict
            required: True
            suboptions:
                host:
                    description: Hostname or IP address of the Gluware Control server.
                    type: string
                username:
                    description: Username for authentication with Gluware Control.
                    type: string
                password:
                    description: Password for authentication with Gluware Control.
                    type: string
                trust_https_certs:
                    description: Bypass HTTPS certificate verification.
                    type: boolean
        glu_device_id:
            description:
                - ID of the device within Gluware.
                - The glu_devices inventory plugin automatically supplies this variable.
            type: string
            required: False
        org_name:
            description:
                - Organization name the device is in within Gluware.
            type: string
            required: False
        name:
            description:
                - Target device name within Gluware Control.
            type: string
            required: False
        data:
            description:
                - Key/Value pairs to update for the target device.
            type: dict
            required: True
'''

EXAMPLES = r'''
    #
    # Update Gluware Control attribute (including custom attributes) values for the current device
    #
    - name: Update the custom attribute playbook_date with the current date in Gluware Control
      gluware_inc.control.glu_update_device_attributes:
        org_name: "gluware_organization"
        name: "{{inventory_hostname}}"
        gluware_control: "{{control}}"
        data:
          playbook_date: "{{ lookup('pipe','date +%Y-%m-%d-%H-%M-%S') }}"

    - name: Update the custom attribute playbook_date with the current date in Gluware Control
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
#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Gluware Inc.

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import Request
import socket
import http.client as httplib
import urllib.error as urllib_error
import re
import json
import os
from ansible_collections.gluware_inc.control.plugins.module_utils.gluware_utils import GluwareAPIClient

try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin


def run_module():
    module_args = dict(
        org_name=dict(type='str', required=False),
        name=dict(type='str', required=False),
        glu_device_id=dict(type='str', required=False),
        data=dict(type='dict', required=True),
        gluware_control=dict(
            type='dict',
            required=True,
            options=dict(
                host=dict(type='str', required=False),
                username=dict(type='str', required=False),
                password=dict(type='str', required=False),
                trust_any_host_https_certs=dict(type='bool', required=False, default=False)
            )
        )
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[['glu_device_id', 'org_name']],
        mutually_exclusive=[['glu_device_id', 'org_name']],
        supports_check_mode=False
    )
    org_name = module.params.get('org_name')
    name = module.params.get('name')
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
            module.fail_json(msg=f"Missing required connection parameter: {key}", changed=False)

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

    get_device = True

    if glu_device_id:
        # Only glu_device_id should be used
        if org_name or name:
            module.warning_json(msg="When 'glu_device_id' is specified, 'org_name' and 'name' must not be set. Only using glu_device_id")
    else:
        # org_name and name must both be provided
        if not org_name or not name:
            module.fail_json(msg="Both 'org_name' and 'name' are required when 'glu_device_id' is not provided.")
        request_payload = {
            "url_username" : api_dict['username'],
            "url_password": api_dict['password'],
            "validate_certs" : not api_dict['trust_any_host_https_certs'],
            "force_basic_auth" : True,
            "headers" : http_headers
        }
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    api_url = urljoin(api_host, '/api/devices/' + glu_device_id)
    
    if not glu_device_id:
        module.fail_json(msg="No Gluware ID found for device", changed=False)

    api_data = module.params['data']

    http_body = json.dumps(api_data)

    try:
        response = request_handler.put(api_url, data=http_body)
    except (ConnectionError, httplib.HTTPException, socket.error, urllib_error.URLError) as e:
        error_msg = f'Gluware Control call failed: {str(e)}'
        if 'Bad Request' in error_msg:
            error_msg = 'Invalid attribute(s) or values for the device. Data provided: ' + http_body
        module.fail_json(msg=error_msg, changed=False)

    if response.status != 200:
        error_msg = f"Unexpected response from Gluware Control: HTTP {response.status} - {response.reason}"
        module.fail_json(msg=error_msg, changed=False)

    result = dict(changed=True)
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()


