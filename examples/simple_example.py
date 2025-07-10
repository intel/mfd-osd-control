# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT

# Put here only the dependencies required to run the module.
# Development and test requirements should go to the corresponding files.
"""Simple example of usage."""

import logging

from mfd_osd_control import OsdController, RefreshMode, OsType, ActiveBootType

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

osd = OsdController(base_url="osd.com")

list_of_oses = osd.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.DISKLESS)
logger.log(level=logging.DEBUG, msg=f"List of OSes: {list_of_oses}")

if not osd.does_host_exist(mac="00:11:22:AA:BB:CC"):
    osd.add_host(mac="00:11:22:AA:BB:CC", os=list_of_oses[0], active_boot_type=ActiveBootType.DISKLESS, refresh=RefreshMode.ONCE)
    host_details = osd.get_host_details(mac="00:11:22:AA:BB:CC")
    logger.log(level=logging.DEBUG, msg=f"Details of host: {host_details}")
    osd.alter_host(mac="00:11:22:AA:BB:CC", diskless_os=list_of_oses[1])
    ip_addr = osd.get_host_ip(mac="00:11:22:AA:BB:CC")
    logger.log(level=logging.DEBUG, msg=f"IP address for mac 00:11:22:AA:BB:CC: {ip_addr}")
    osd.delete_host(mac="00:11:22:AA:BB:CC")
