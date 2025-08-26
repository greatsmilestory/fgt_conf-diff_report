Many FortiGate engineers know there aren't many projects integrating with FortiManager, so I considered creating this code might be pointless. However, I wrote it to reduce the burden on FortiGate engineers, even if it's only used once.

Integration in environments operating multiple FortiGates and vDOMs is truly difficult due to numerous duplicate objects with identical names.

This code helps FortiGate engineers prevent errors when integrating with FortiManager by comparing attribute values for duplicate objects (addresses, address groups, services, service groups) and generating a report. This is especially useful when managing multiple pre-configured FortiGates or vDOM environments.

Of course, final verification remains your responsibility.

This code has been tested on Windows OS with Python 3.12.
It has not been tested on macOS.

Python version 3.12 or higher must be installed on the device where the fgt_diff_addr_service.py file is executed.

In the CMD window, navigate to the directory where fgt_diff_addr_service.py was downloaded and enter the command: py fgt_diff_addr_service.py. When the GUI explorer window appears, select the FortiGate Conf file. (You can select one or multiple Conf files.)

The FortiGate Conf file will be analyzed, and the report will automatically appear in your web browser.



<img width="1913" height="934" alt="image" src="https://github.com/user-attachments/assets/2f766205-ed7a-408d-b956-4be0706e160e" />
