# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Jonathan Mainguy <jon@soh.re>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r'''
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
              type: boolean
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
    required: False
  name:
    description:
      - Target device name within Gluware Control.
    type: str
    required: False
'''
