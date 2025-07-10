> [!IMPORTANT]
> This project is under development. All source code and features on the main branch are for the purpose of testing or evaluation and not production ready.

# MFD OSD Control

Module for controlling entries in OSD.

### Available methods

- check if host exists 
    ```python
    does_host_exist(mac: str)
    ```
    * `mac`: MAC address
    * return `bool` value indicating whether host exists or not

- get host details
    ```python
    get_host_details(mac: str)
    ```
    * `mac`: MAC address
    * return `dict` with host information

- add host
    ```python
    add_host(mac: str, os: str, active_boot_type: ActiveBootType, refresh: RefreshMode, description: str)
    ```
    * `mac`: MAC address
    * `os`: OS key
    * `active_boot_type`: active boot type
    * `refresh`: refresh mode
    * `description`: optional description for host

- alter host
    ```python
    alter_host(mac: str, diskless_os: str, imageloader_os: str, iso_os: str, active_boot_type: ActiveBootType, refresh: RefreshMode, description: str)
    ```
    * `mac`: MAC address
    * `diskless_os`: Diskless OS key
    * `imageloader_os`: ImageLoader OS key
    * `iso_os`: ISO OS key
    * `active_boot_type`: active boot type
    * `refresh`: refresh mode
    * `description`: optional description for host

- delete host
    ```python
    delete_host(mac: str)
    ```
    * `mac`: MAC address

- get available OSes
    ```python
    get_available_oses(mac: str, os_type: OsType)
    ```
    * `mac`: MAC address
    * `os_type`: OS type
    * return `list` of available OSes

- get host IP
    ```python
    get_host_ip(mac: str)
    ```
    * `mac`: MAC address
    * return `IPv4Address` object with retrieved IP address


## Usage

```python
import logging

from mfd_osd_control import OsdController, RefreshMode, OsType, ActiveBootType

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

osd = OsdController(base_url="osd.example.com")

list_of_oses = osd.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.DISKLESS)
logger.log(level=logging.DEBUG, msg=list_of_oses)

if not osd.does_host_exist(mac="00:11:22:AA:BB:CC"):
    osd.add_host(mac="00:11:22:AA:BB:CC", os=list_of_oses[0], active_boot_type=ActiveBootType.DISKLESS, refresh=RefreshMode.ONCE)
    host_details = osd.get_host_details(mac="00:11:22:AA:BB:CC")
    logger.log(level=logging.DEBUG, msg=host_details)
    osd.alter_host(mac="00:11:22:AA:BB:CC", diskless_os=list_of_oses[1])
    ip_addr = osd.get_host_ip(mac="00:11:22:AA:BB:CC")
    logger.log(level=logging.DEBUG, msg=ip_addr)
    osd.delete_host(mac="00:11:22:AA:BB:CC")
```

## OS supported:

* Linux
* Windows
* ESXi
* FreeBSD

## Issue reporting

If you encounter any bugs or have suggestions for improvements, you're welcome to contribute directly or open an issue [here](https://github.com/intel/mfd-osd-control/issues).