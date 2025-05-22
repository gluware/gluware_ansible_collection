#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Gluware Inc.

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
    module: glu_run_discover_device_attributes 
    short_description: Perform device discover action on Gluware device to update attributes
    description:
        - Runs device discover action on specified devices in the Ansible playbook.
        - By default this module will use device_id parameter to find the device in Gluware.
        - This module supports specifying the friendly name of the device if the organization name is specified as well instead of supplying the device_id parameter.  
    version_added: '2.8'
    author:
    - John Anderson (@gluware-inc)
    - Oleg Gratwick (@ogratwick-gluware)
    options:
    extends_documentation_fragment:
    - gluware_inc.control.gluware_control

'''

EXAMPLES = r'''
    #
    # Trigger a Gluware Control discover device attributes for the current device
    #
    - name: Discover device properties
      gluware_inc.control.glu_run_discover_device_attributes:
        org_name: "gluware_organization"
        name: "{{inventory_hostname}}"
        gluware_control: "{{control}}"

    - name: Discover device properties
      gluware_inc.control.glu_run_discover_device_attributes:
        glu_device_id: "340b28a3-72b9-4708-852e-9c7490e2e650"
        gluware_control: "{{control}}"


'''


try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin


def run_module():

    # Module parameters
    module_args = GluwareAPIClient.gluware_common_params()

    # Initialize the AnsibleModule to use in communication from and to the
    # code (playbook, etc) interacting with this module.
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
                msg=f"Missing required connection parameter: {key}", changed=False)

    # All the required values exist, so use the information in the file for the connection information.
    api_host = api_dict.get('host')

    # Make sure there is a http or https preference for the api_host
    api_host = api_dict['host']
    if not re.match('(?:http|https)://', api_host):
        api_host = 'https://{host}'.format(host=api_host)

    # Make sure the Content-Type is set correctly.. otherwise it defaults to application/x-www-form-urlencoded which
    # causes a 400 from Gluware Control
    http_headers = {
        'Content-Type': 'application/json'
    }

    # Create the request_handler to make the calls with.
    request_handler = Request(
        url_username=api_dict['username'],
        url_password=api_dict['password'],
        validate_certs=not api_dict['trust_any_host_https_certs'],
        force_basic_auth=True,
        headers=http_headers
    )

    # Default result JSON object
    get_device = True

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
        request_payload = {
            "url_username": api_dict['username'],
            "url_password": api_dict['password'],
            "validate_certs": not api_dict['trust_any_host_https_certs'],
            "force_basic_auth": True,
            "headers": http_headers
        }
        glu_api = GluwareAPIClient(request_payload, api_host)
        glu_device = glu_api._get_device_id(name, org_name)
        glu_device_id = glu_device.get('id')

    # This api call is for Gluware Control.
    api_url = urljoin(api_host, '/api/devices/discover')
    if not glu_device_id:
        module.fail_json(msg="No Gluware ID found for device", changed=False)
    # Create the body of the request.
    api_data = {
        "devices": [glu_device_id]
    }
    http_body = json.dumps(api_data)

    # Make the actual api call.
    try:
        response = request_handler.post(api_url, data=http_body)
    except (ConnectionError, httplib.HTTPException, socket.error, urllib_error.URLError) as e2:
        error_msg = 'Gluware Control call failed: {msg}'.format(msg=e2)
        module.fail_json(msg=error_msg, changed=False)

    # Check for 204 No Content response
    if response.status != 204:
        error_msg = f"Unexpected response from Gluware Control: HTTP {response.status} - {response.reason}"
        module.fail_json(msg=error_msg, changed=False)

    result = dict(changed=True)
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
