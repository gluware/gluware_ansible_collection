# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Gluware Inc.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import time

# Python 2/3 compatible urllib imports
try:
    # Python 3
    from urllib.parse import urljoin
except ImportError:
    # Python 2
    from urlparse import urljoin  # type: ignore

# Prefer Ansible-provided client + exceptions (satisfies ansible-test/ansible-lint)
from ansible.module_utils.urls import (
    Request,
    SSLValidationError,
    ConnectionError
)


class GluwareAPIClient:
    def __init__(self, request_handler, api_url):
        """
        request_handler is expected to be a dict containing (optionally):
          - headers: dict of default headers
          - url_username: str
          - url_password: str
          - validate_certs: bool (default True)
        """
        self.api_url = api_url.rstrip('/')

        # Initialize an Ansible Request "session" with sensible defaults
        self.session = Request(
            headers=request_handler.get("headers", {}),
            url_username=request_handler.get("url_username"),
            url_password=request_handler.get("url_password"),
            validate_certs=request_handler.get("validate_certs", True),
            # Match requests' preemptive Basic Auth behavior
            force_basic_auth=True,
        )

    def _url(self, path):
        return "{}/{}".format(self.api_url, path.lstrip('/'))

    def _open(self, method, url, **kwargs):
        """
        Wrapper around Request.open with unified error handling.
        Returns a file-like HTTPResponse on success.
        """
        try:
            return self.session.open(method, url, **kwargs)
        except SSLValidationError as err:
            raise Exception("SSL validation failed for '{}': {}".format(url, err))
        except ConnectionError as err:
            raise Exception("Connection error for '{}': {}".format(url, err))
        except Exception as err:
            raise Exception("Unexpected error for '{}': {}".format(url, err))

    def _read_json(self, resp, url):
        """
        Read and decode JSON from an HTTPResponse; raise helpful error if invalid.
        """
        try:
            raw = resp.read()
            if raw is None:
                return None
            text = raw.decode('utf-8', errors='replace')
            if not text:
                return None
            return json.loads(text)
        except ValueError:
            # Non-JSON response
            snippet = ''
            try:
                snippet = text[:200]  # type: ignore[name-defined]
            except Exception:
                pass
            raise Exception("Non-JSON response from {}: {}".format(url, snippet))

    def _get_org_name(self, org_name):
        url = urljoin(self.api_url, '/api/organizations?name=' + org_name)
        resp = self._open('GET', url)
        return self._read_json(resp, url)

    @staticmethod
    def gluware_common_params():
        return dict(
            org_name=dict(type='str', required=False),
            name=dict(type='str', required=False),
            glu_device_id=dict(type='str', required=False),
            timeout=dict(type='int', required=False, default=60),
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
        url = urljoin(self.api_url, '/api/devices?orgId=' + org_id + '&fields=name,id')
        resp = self._open('GET', url)
        devices = self._read_json(resp, url) or []

        # Try exact name first
        for device in devices:
            if device.get('name') == name:
                return device

        raise Exception("Device '{}' not found in org '{}'".format(name, org_name))

    def _get_work_status(self, id, timeout):
        url = urljoin(self.api_url, '/api/work/' + id)
        deadline = time.time() + timeout
        last_status = None
        time.sleep(5)  # initial backoff
        poll_interval = 5

        while time.time() < deadline:
            resp = self._open('GET', url, timeout=30)
            data = self._read_json(resp, url) or {}
            status = str(data.get("status", "")).upper()

            if status in ("RUNNING", ""):
                last_status = status
            elif status in ("SUCCESSFUL", "FAILED"):
                return status

            last_status = status
            time.sleep(poll_interval)

        raise Exception("Timed out waiting for API state (last status={0}).".format(repr(last_status)))

    def _get_work_output(self, id, type_work):
        url = urljoin(self.api_url, '/api/work/' + id + '/results/' + type_work)
        resp = self._open('GET', url)
        return self._read_json(resp, url)

    def _get_device_ids(self, name, org_name):
        org_list = self._get_org_name(org_name)
        if not org_list:
            raise Exception("Device '{}' not found in org '{}'".format(name, org_name))

        org_id = org_list[0].get('id')
        url = urljoin(self.api_url, '/api/devices?orgId=' + org_id + '&fields=name,id')
        resp = self._open('GET', url)
        devices = self._read_json(resp, url) or []
        by_name = {o["name"]: o["id"] for o in devices}

        # Warn about any names that aren't present
        missing = [n for n in name if n not in by_name]
        # Keep only the ids for names that exist, preserving order
        ids = [by_name[n] for n in name if n in by_name]
        return ids

    def _get_device(self, name, org_name):
        org_list = self._get_org_name(org_name)
        org_id = org_list[0].get('id')
        url = urljoin(self.api_url, '/api/devices?orgId=' + org_id + '&fields=name,id')
        resp = self._open('GET', url)
        devices = self._read_json(resp, url) or []

        # Try exact name first
        for device in devices:
            if device.get('name') == name:
                return device

    def _get_rpa_status(self, id, timeout):
        url = urljoin(self.api_url, '/api/workflows/activity/' + id["workflowActivityId"])
        deadline = time.time() + timeout
        last_status = None
        time.sleep(5)  # initial backoff
        poll_interval = 5

        while time.time() < deadline:
            resp = self._open('GET', url, timeout=30)
            data = self._read_json(resp, url) or {}
            status = str(data.get("status", "")).upper()
            if status in ("RUNNING", ""):
                last_status = status
            elif status in ("COMPLETED", "FAILED"):
                return data
            last_status = status
            time.sleep(poll_interval)

        raise Exception("Timed out waiting for API state (last status={0}).".format(repr(last_status)))
