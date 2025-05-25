# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Gluware Inc.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from urllib.parse import urljoin

HAS_REQUESTS = True
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    HAS_REQUESTS = False


class GluwareAPIClient:
    def __init__(self, request_handler, api_url):
        self.api_url = api_url.rstrip('/')

        if not HAS_REQUESTS:
            raise Exception('requests module is not installed. Please install module to continue.')

        self.session = requests.Session()
        self.session.headers.update(request_handler.get("headers", {}))
        self.auth = HTTPBasicAuth(
            request_handler.get("url_username"),
            request_handler.get("url_password")
        )
        self.verify = request_handler.get("validate_certs", True)

    def _url(self, path):
        return "{}/{}".format(self.api_url, path.lstrip('/'))

    def _get_org_name(self, org_name):
        url = urljoin(self.api_url, '/api/organizations?name=' + org_name)
        try:
            response = self.session.get(
                url, auth=self.auth, verify=self.verify)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
            raise Exception("GET request to {} failed: {}".format(url, err))

    @staticmethod
    def gluware_common_params():
        return dict(
            org_name=dict(type='str', required=False),
            name=dict(type='str', required=False),
            glu_device_id=dict(type='str', required=False),
            gluware_control=dict(
                type='dict',
                required=True,
                options=dict(
                    host=dict(type='str', required=False),
                    username=dict(type='str', required=False),
                    password=dict(type='str', required=False, no_log=True),
                    trust_any_host_https_certs=dict(
                        type='bool', required=False, default=False)
                )
            )
        )

    def _get_device_id(self, name, org_name):
        org_list = self._get_org_name(org_name)
        if not org_list:
            raise Exception("Device '{}' not found in org '{}'".format(name, org_name))
        org_id = org_list[0].get('id')
        url = urljoin(self.api_url, '/api/devices?orgId=' + org_id)
        try:
            response = self.session.get(
                url, auth=self.auth, verify=self.verify)
            response.raise_for_status()
            devices = response.json()
            found = False
            for device in devices:
                if device.get('name') == name:
                    found = True
                    return device
            if found is False:
                for device in devices:
                    if device.get('discoveredHostname') == name:
                        found = True
                        return device
            else:
                raise Exception(
                    f"Device '{name}' not found in org '{org_name}'")

        except requests.RequestException as err:
            raise Exception(f"GET request to {url} failed: {err}")
