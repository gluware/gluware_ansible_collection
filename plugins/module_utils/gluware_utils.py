#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Gluware Inc.
import json
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
            raise Exception(f"Requests library not found")

        self.session = requests.Session()
        self.session.headers.update(request_handler.get("headers", {}))
        self.auth = HTTPBasicAuth(
            request_handler.get("url_username"),
            request_handler.get("url_password")
        )
        self.verify = request_handler.get("validate_certs", True)  

    def _url(self, path):
        return f"{self.api_url}/{path.lstrip('/')}"

    def _get_org_name(self, org_name):
        url = urljoin(self.api_url, '/api/organizations?name=' + org_name)
        try:
            response = self.session.get(url, auth=self.auth, verify=self.verify)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
            raise Exception(f"GET request to {url} failed: {err}")
    
    def _get_device_id(self, name, org_name):
        org_list = self._get_org_name(org_name)
        if not org_list:
            self.module.fail_json(msg=f"No organization found with name {org_name}")
        org_id = org_list[0].get('id')
        url = urljoin(self.api_url, '/api/devices?orgId=' + org_id)
        try:
            response = self.session.get(url, auth=self.auth, verify=self.verify)
            response.raise_for_status()
            devices = response.json()
            found = False
            for device in devices:
                if device.get('name') == name:
                    found = True
                    return device
            if found == False:
                for device in devices:  
                    if device.get('discoveredHostname') == name:
                        found = True
                        return device
            else:
                raise Exception(f"Device '{name}' not found in org '{org_name}'")
            
        except requests.RequestException as err:
            raise Exception(f"GET request to {url} failed: {err}")