# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Jonathan Mainguy <jon@soh.re>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
  DOCUMENTATION = r'''
options:
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