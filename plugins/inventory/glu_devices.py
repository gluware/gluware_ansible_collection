# -*- coding: utf-8 -*-

# Copyright: (c) 2019-2020, Gluware Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = '''
    name: glu_devices
    short_description: Gluware Control Inventory Source
    description:
        - Get inventory from Device Manager in Gluware Control.
        - Uses a YAML configuration file that ends with C(.yml/.yaml) for the connection information of the Gluware Control system.
        - This plugin is able to gather credentials that are set for devices within Gluware.
          If this is desired behavior, ensure the user you are using to authenticate to Gluware has System Developer role with Superuser Privileges.
        - It is recommended to create a specific user that has access to only the target Gluware organization when using the inventory plugin to avoid having
          groups with devices from separate organizations.
        - If there are any Gluware Control custom attributes with values on the devices that start with C(ansible_var_) then those variables will be added to
          the host (minus the C('ansible_var_') part).
        - If there is a Gluware Control custom field of C('ansible_connection') on the device then that will be the connection for that host.
          Otherwise C'network_cli') will be the connection.
        - If there is a Gluware Control custom field of C('ansible_network_os') on the device then that will be the 'ansible_network_os' for that host.
          Otherwise 'discoveredOs' (if available) will be the C('ansible_network_os') for that host.
    author:
        - John Anderson (@gluware-inc)
        - Oleg Gratwick (@ogratwick-gluware)
    options:
        plugin:
            description: This tells ansible (through the auto inventory plugin) this is a source file for the glu_devices plugin.
            required: True
            choices: ['glu_devices', 'gluware_inc.control.glu_devices']
        host:
            description: The network address or name of your Gluware Control system host.
            type: str
            env:
                - name: GLU_CONTROL_HOST
            required: True
        username:
            description: The user used to access devices (inventories) from the Gluware Control system.
            type: str
            env:
                - name: GLU_CONTROL_USERNAME
            required: True
        password:
            description: The password for the username of the Gluware Control system.
            type: str
            env:
                - name: GLU_CONTROL_PASSWORD
            required: True
        trust_any_host_https_certs:
            description:
                - Specify whether Ansible should verify the SSL certificate of https calls on the Control Gluware system host.
                - This is used for self-signed Gluware Control Systems.
            type: bool
            default: False
            env:
                - name: GLU_CONTROL_TRUST_ANY_HOST_HTTPS_CERTS
            required: False
            aliases: [ verify_ssl ]
        compose:
            description:
                - Add a host variable from Jinja2 expressions.
                - The keys of the dictionary are the host variables.
                - The values of the dictionary are Jinja2 exzpresions.
                - The Jinja2 expressions can use Gluware Control device attributes (including custom attributes).
            type: dict
            required: False
        groups:
            description:
                - Define groups for a host based on Jinja2 conditionals.
                - The keys of the dictionary are the groups.
                - The values of the dictionary are Jinja2 conditionals where a truthful condition causes current host be in the group specified in the key.
                - The Jinja2 conditionals can use Gluware Control device attributes (including custom attributes).
            type: dict
            required: False
        keyed_groups:
            description:
                - Define groups for a host from Jinja2 expresions.
                - Each list item is a dictionary with the following keys.
                - (key) a required Jinga 2 expression
                - (prefix) a optional text to prefix the value of the (key) expression. The default is a empty string.
                - (separator) a optional text to separate the (prefix) and (key) expression. The default is a underscore '_'.
                - (parent_group) a optional text to specify the parent group for this group.
                - The Jinja2 expressions can use Gluware Control device attributes (including custom attributes).
            type: list
            elements: dict
            required: False
        variable_map:
            description:
                - (DEPRECATED) use the 'compose' option. 'compose' eclipses the functionality of this option.
                - This option is a dictionary where the keys are variable names of Gluware Control devices attributes (including custom attributes).
                - The values of the dictionary are strings that specify the variable names on the host in Ansible.
            type: dict
            required: false
'''

EXAMPLES = r'''
---
#
# Minimal Configuration for *glu_devices.yml files where no GLU_CONTROL_* environment variables are defined.
plugin: glu_devices
host: 'https://10.0.0.1'
username: <user name in Gluware Control system for device API calls>
password: <password for user name>

---
#
# Configuration to use a Gluware Control system that has a self-signed certificate.
plugin: gluware.control.glu_devices
host: 'https://10.0.0.1'
username: <user name in Gluware Control system for device API calls>
password: <password for user name>
trust_any_host_https_certs: True
---

#
# Configuration to map the Gluware device attribute 'discoveredSerialNumber' to the Ansible host variable 'serial_num'
plugin: glu_devices
host: 'https://10.0.0.1'
username: <user name in Gluware Control system for device API calls>
password: <password for user name>
trust_any_host_https_certs: True
compose:
    serial_num : discoveredSerialNumber

---
#
# Configuration to have Gluware Control devices grouped under the value custom attribute 'Area' where 'Area' is also the parent group.
plugin: glu_devices
host: 'https://10.0.0.1'
username: <user name in Gluware Control system for device API calls>
password: <password for user name>
trust_any_host_https_certs: True
keyed_groups:
    - key: Area
      separator: ''
      parent_group: Area

---

#
# Configuration to have Gluware Control devices grouped under 'front_devices' where the text 'Front' is found in the 'Area' custom attribute.
plugin: glu_devices
host: 'https://10.0.0.1'
username: <user name in Gluware Control system for device API calls>
password: <password for user name>
trust_any_host_https_certs: True
groups:
    front_devices: "'Front' in Area"
#Advanced example for composition
plugin: glu_devices
host: 'https://10.0.0.1'
username: <user name in Gluware Control system for device API calls>
password: <password for user name>
trust_any_host_https_certs: True
compose:
    glu_serial_num : discoveredSerialNumber
    glu_asset_tag : Asset Tag
    glu_audit_status : auditStatus
    glu_drift_status : driftStatus
    glu_critical_adv : custFields["Critical Advisories"]
    glu_discovery_status : discoveryStatus
    glu_access_status : accessStatus
    glu_connection_method : connectionMethod
    glu_description : "description"
    glu_discovered_type : discoveredTypeBase
    glu_environment : environment
    glu_name : "name"
    glu_props_domains : nodeProperties.Domains
    glu_props_assembly : nodeProperties["Assembly Policy"]
    glu_props_prov_summary : nodeProperties["Feature Provisioning Summary"]
    glu_org_id : orgId
    glu_conn_ip : connectionInformation.ip
    glu_conn_type : connectionInformation.type
    glu_site_code : sideCodeName
    glu_site_name : sideName
    glu_creds_rule : credsName
    glu_props_licenses : discoveredLicenses

'''

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.module_utils._text import to_native
from ansible.errors import AnsibleError
import http.client as httplib
import socket
import urllib.error as urllib_error
from requests.auth import HTTPBasicAuth
import json
import re
import os
from urllib.error import URLError
from urllib.request import Request as URLRequest, build_opener, HTTPBasicAuthHandler, HTTPSHandler

# Python 2/3 Compatibility
try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin
HAS_REQUESTS = True
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    HAS_REQUESTS = False
# Mapping between the discoveredOs variable and ansible_network_os
DiscoveredOSToAnsibleNetworkOS = {
    'NX-OS': 'cisco.nxos.nxos',
    'IOS/IOS XE': 'cisco.ios.ios',
    'Junos OS': 'junipernetworks.junos.junos',
    'ArubaOS': 'arubanetworks.aoscx.aoscx',
    'PAN-OS': 'fortinet.fortios.fortios',
    'ArubaOS-CX': 'arubanetworks.aoscx.aoscx',
    'EOS': 'arista.eos.eos',
    'ExtremeXOS': 'extreme.exos.exos',
    'ASA': 'cisco.asa.asa',
    'AireOS': 'cisco.aireos.aireos'
}


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "gluware_inc.control.glu_devices"
    INVENTORY_FILE_SUFFIXES = "glu_devices.yml"

    def __init__(self):
        super(InventoryModule, self).__init__()

        self.group_prefix = 'glu_'
        if not HAS_REQUESTS:
            module.fail_json(msg='requests module is not installed. Please install module to continue.)

    @staticmethod
    def _convert_group_name(group_name):
        '''
          Convert group names to valid characters that can be a directory on a file system.
        '''
        group_name = re.sub('[^a-zA-Z0-9]', '_', group_name)
        return group_name

    def _api_call(self, request_handler, api_url, api_url_2):
        '''
            Make the api call for the api_url with the request_handler and on success return object with data.
            If api_url fails then try api_url_2.
        '''
        # Make the actual api call.
        try:
            response = request_handler.get(api_url)
        except (ConnectionError, httplib.HTTPException, socket.error, urllib_error.URLError):
            # If the first call returns a URL error then try this second call.
            try:
                response = request_handler.get(api_url_2)
            except (ConnectionError, httplib.HTTPException, socket.error, urllib_error.URLError) as e2:
                error_msg = 'Gluware Control call2 failed: {msg}'.format(msg=e2)
                raise AnsibleError(to_native(error_msg))

        # Read in the JSON response to a object.
        try:
            read_response = response.read()
            obj_response = json.loads(read_response)
            return obj_response
        except (ValueError, TypeError) as e:
            error_msg = 'Gluware Control call response failed to be parsed as JSON: {msg}'.format(
                msg=e)
            raise AnsibleError(to_native(error_msg))

    def _update_inventory_obj(self, api_devices):
        '''
            Take the api_devices object and update the self.inventory object
        '''
        # pprint.pprint(api_devices)

        option_compose = self.get_option('compose')
        option_groups = self.get_option('groups')
        option_keyed_groups = self.get_option('keyed_groups')

        for device_obj in api_devices:
            device_name = device_obj.get('name')
            # Set the glu_device_id to work with the gluware ansible modules.
            glu_device_id = device_obj.get('id')

            # Try to used the discoveredOs from the device.
            #   If that is not found the try to use the ansible_network_os on the device.
            network_os = ''
            discovered_os = device_obj.get('discoveredOs')

            if discovered_os:
                network_os = DiscoveredOSToAnsibleNetworkOS.get(discovered_os)
            if not network_os:
                network_os = device_obj.get('ansible_network_os')
            if not network_os:

                network_os = discovered_os

            # In case the ansible connection is overridden.
            ansible_connection = device_obj.get('ansible_connection')
            if device_name:
                connection_info_obj = device_obj.get('connectionInformation')
                if connection_info_obj:
                    connect_ip = connection_info_obj.get('ip')
                    connect_port = connection_info_obj.get('port')
                    connect_info = connection_info_obj.get('credentials')
                    if connect_info:
                        connect_username = connect_info.get('userName')
                        connect_password = connect_info.get('password')
                    else:
                        connect_username = connection_info_obj.get('userName')
                        connect_password = connection_info_obj.get('password')
                    connect_enable_password = connection_info_obj.get(
                        'enablePassword')

                    # Special logic if password and enable password is not available.
                    if not connect_password:
                        connect_password = device_obj.get('x_word')
                    if not connect_enable_password:
                        connect_enable_password = device_obj.get('x_e_word')

                    # Check that that the device is not already added by some other inventory plugin.
                    if not self.inventory.get_host(device_name):
                        group = None
                        if network_os:
                            group = self._convert_group_name(
                                device_obj.get('discoveredOs'))
                            self.inventory.add_group(group)
                        host = self.inventory.add_host(
                            device_name, group, connect_port)

                    site_path = device_obj.get('sitePath')
                    if site_path:
                        site_group = self._convert_group_name(site_path)
                        self.inventory.add_group(site_group)
                        self.inventory.add_host(device_name, site_group)

                        # Set the ansible_network_os no matter what.  This is so it is not undefined in the playbook.
                        self.inventory.set_variable(
                            host, 'ansible_network_os', network_os)

                        if connect_ip:
                            self.inventory.set_variable(
                                host, 'ansible_host', connect_ip)
                        if connect_username:
                            self.inventory.set_variable(
                                host, 'ansible_user', connect_username)
                        if connect_password:
                            self.inventory.set_variable(
                                host, 'ansible_password', connect_password)
                        if ansible_connection:
                            self.inventory.set_variable(
                                host, 'ansible_connection', ansible_connection)

                        # Gluware device id is set on this inventory item to be used with other Gluware modules.
                        if glu_device_id:
                            self.inventory.set_variable(
                                host, 'glu_device_id', glu_device_id)

                        # For any device_obj properties that start with 'ansible_var_' add that variable (minus the 'ansible_var_' part) to the host.
                        for prop_name, prop_val in device_obj.items():
                            if prop_name.startswith('ansible_var_'):
                                ansible_var = prop_name[len('ansible_var_'):]
                                if ansible_var:
                                    self.inventory.set_variable(
                                        host, ansible_var, prop_val)

                        # If there is a variable_map then look for the variable in the device_obj and assign it to the ansible_var_name to the host.
                        variable_map = self.get_option('variable_map')
                        if variable_map:
                            for gluprop_name, ansible_var_name in variable_map.items():
                                deviceprop_val = device_obj.get(gluprop_name)
                                if deviceprop_val:
                                    self.inventory.set_variable(
                                        host, ansible_var_name, deviceprop_val)
                if option_compose:
                    self._set_composite_vars(
                        option_compose, device_obj, device_name)
                if option_groups:
                    self._add_host_to_composed_groups(
                        option_groups, device_obj, device_name)
                if option_keyed_groups:
                    self._add_host_to_keyed_groups(
                        option_keyed_groups, device_obj, device_name)

        # Finalize inventory
        self.inventory.reconcile_inventory()

    def verify_file(self, path):
        '''
            Called by ansible first to verify if the path is valid for this inventory plugin.
        '''
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith('.yml') or path.endswith('.yaml'):
                return True
        return False

    def parse(self, inventory, loader, path, cache=True):
        '''
            Called by ansible second to fill in the passed inventory object for the specified path.
            The self.verify_file() was called first so state could have been set on the self object there
            that can be used here.
        '''

# Use the super classes functionality to setup the self object correcly.
        super(InventoryModule, self).parse(inventory, loader, path)
        self._read_config_data(path)

        # Setup for the API call for the data for the inventory.
        api_host = self.get_option('host')
        if not api_host:
            api_host = os.environ.get('GLU_CONTROL_HOST')

        if not re.match('(?:http|https)://', api_host):
            api_host = 'https://{host}'.format(host=api_host)

        # This api call is for Gluware Control 3.6 and greater.
        api_url_1 = urljoin(api_host, '/api/devices?showPassword=true')
        # This api call is for Gluware Control 3.5.
        api_url_2 = urljoin(api_host, '/api/devices')

        api_user = self.get_option('username')
        if not api_user:
            api_user = os.environ.get('GLU_CONTROL_USERNAME')

        api_password = self.get_option('password')
        if not api_password:
            api_password = os.environ.get('GLU_CONTROL_PASSWORD')

        api_trust_https = self.get_option('trust_any_host_https_certs')
        if not api_trust_https:
            api_trust_https = os.environ.get(
                'GLU_CONTROL_TRUST_ANY_HOST_HTTPS_CERTS')

        api_devices = None
        try:
            with make_authenticated_request(api_url_1, api_user, api_password, not api_trust_https, timeout=30) as response:
                api_devices = json.loads(response.text)
        except URLError:
            with make_authenticated_request(api_url_2, api_user, api_password, not api_trust_https, timeout=30) as response:
                api_devices = json.loads(response.read())
        # Process the API data into the inventory object.
        self._update_inventory_obj(api_devices)


def make_authenticated_request(url, user, password, validate_certs=True, timeout=30):
    response = requests.get(
        url,
        auth=HTTPBasicAuth(user, password),
        verify=validate_certs,
        timeout=timeout
    )
    response.raise_for_status()
    return response
