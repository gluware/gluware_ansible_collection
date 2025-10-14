====================================================
Gluware Control Collection Release Notes
====================================================

.. contents:: Topics

This changelog describes changes after version 1.1.2.

v2.0.0
=======

Release Summary
---------------
This release updates code to not require the requests module.  Additionally
support has been added for polling results of jobs executed in Gluware to return back to
Ansible execution. 

Minor Changes
-------------
- Requests module no longer required for collections utilization
- Polling functions added to monitor the progress of Gluware jobs and return output
- Code updated to capture HTTP output messages
- Added filter capabilities to the inventory plugin
- Added example playbooks directory for reference

New Modules
-------------
- glu_audit_config_batch - Allows for user to run audit on all devices in the play as a single audit execution in Gluware
- glu_backup - Executes action to backup device in Gluware
- glu_cm_preview - Executes Config Modeling Preview on device in Gluware
- glu_cm_provision - Executes Config Modeling Provisioning on device in Gluware
- glu_device_facts - Gathers device information from Gluware on device
- glu_device - Manage lifecycle of devices in Gluware Device Manager
- glu_get_backups - View all available backups for device in Gluware
- glu_restore - Restore the device from a available backup in Gluware
- glu_rpa_workflow - Executes RPA workflow with the device in the play
- glu_rpa_workflow_batch - Executes a single RPA workflow for all devices provided in a task

v1.2.1
=======

Release Summary
---------------
This is the first release of Gluware Control modules with refactored code to support
the use of Ansible collections.

This is a minor release of the ``gluware_inc.control`` collection bundle.  It fixes some of the pylint errors found in the code.

Minor Changes
-------------
- CHANGELOG.rst - Create the changelog filter
- Added util module for common methods
- Updated existing code to support collection naming standards
- Updated existing documentation for modules and plugins
- Added requirement of requests module to be installed for Python
- Added Github workflow to run ansible-test commands for validation and testing
