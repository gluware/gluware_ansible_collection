# Ansible Modules for Gluware Control

## Description
The Gluware Ansible collection provides modules and plugins for Ansible playbooks to interact with the Gluware Control platform.

## Requirements

- Python 3.12+
- Ansible 2.15+

## Installation

### Python Modules and Ansible
```
pip install ansible
```

### Gluware Ansible Collection
Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install gluware.control
```

See using [Ansible collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#installing-collections) for more details.

### Other Installation Options

#### Build From Source

Follow these steps to install from source:

1. ``git clone https://github.com/gluware/gluware_ansible_collection.git``
2. ``cd gluware_ansible_collection``
3. ``ansible-galaxy collection build .``
4. ``ansible-galaxy collection install gluware_inc-control-*.tar.gz``

## Use Cases

### Use Case 1 - Utilize Gluware Device Manager to build your Ansible inventory
When using the Gluware Inventory Plugin `glu_devices`, the plugin witll generate a Ansible Inventory and automatically create groups based on the site the device is assigned to and what OS the device is discovered to be.  The OS discovery should set for each device what connection plugin to use to interact with said device.  

The example below shows how to use the inventory plugin to build your source of truth from Gluware Device Manager:

glu_devices.yml file specifies connection details to your Gluware Control instllation
Example Command: ``ansible-inventory -i glu_devices.yml --list -v``
```
plugin: gluware_inc.control.glu_devices
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
```
### Use Case 2 - Orchestrate lifecycle management of Gluware devices using Ansible playbook with targeted nodes
This example will show how to utilize all Gluware Ansible modules to manage the lifecycle of the device using Ansible playbooks
```
---
- name: "Gluware Node Management"
  hosts: NX_OS
  connection: local
  vars:
    control:
      host: "https://<gluware host>"
      username: "<gluware user>"
      password: "<gluware password>"
      trust_any_host_https_certs: true
  gather_facts: False
  tasks:
    - name: Update device with a description in Gluware Control
      gluware_inc.control.glu_update_device_attributes:
        org_name: "<gluware_org>"
        name: "{{inventory_hostname}}"
        gluware_control: "{{control}}"
        data:
          description : "Gluware Ansible Test"
    - name: Discover Device Properties
      gluware_inc.control.glu_run_discover_device_attributes:
        org_name: "<gluware_org>"
        name: "{{inventory_hostname}}"
        gluware_control: "{{control}}"
    - name: Capture Device Configuration
      gluware_inc.control.glu_capture_config:
        org_name: "<gluware_org>"
        name: "{{inventory_hostname}}"
        gluware_control: "{{control}}"
        description : "Ansible Snapshot"
    - name: Audit Configuration
      gluware_inc.control.glu_audit_config:
        org_name: "<gluware_org>"
        name: "{{inventory_hostname}}"
        gluware_control: "{{control}}"
        description : "Ansible Audit"
        audit_policy: "<Gluware Audit Policy Name>"
```
## Testing
Tested with Ansible Core v2.18

## License Information
GNU General Public License v3.0 or later.

See [LICENSE](https://github.com/gluware/gluware_ansible_collection/blob/main/LICENSE) for the full text of the license.

Link to the license that the collection is published under.
