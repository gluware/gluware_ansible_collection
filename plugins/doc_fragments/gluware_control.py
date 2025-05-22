# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Jonathan Mainguy <jon@soh.re>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
  
  DOCUMENTATION = '''
  ---
  module: glu_capture_config
  short_description: Perform a capture configuration on a Gluware Device to monitor for configuration drift
  description:
    - For the current Gluware device, trigger a capture config in Gluware Control.
    - By default this module will use device_id parameter to find the device in Gluware.
    - Alternatively, friendly name and organization name can be used.
  version_added: '2.8'
  author:
    - John Anderson (@gluware-inc)
    - Oleg Gratwick (@ogratwick-gluware)
  extends_documentation_fragment:
    - gluware_inc.control.gluware_control
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
    description:
      description:
        - Name to associate snapshot with.
      type: str
      required: False
  '''
