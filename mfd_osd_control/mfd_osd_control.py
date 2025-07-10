# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Module for diskless controller."""

import logging
import urllib3
import requests
from enum import Enum
from http import HTTPStatus
from ipaddress import IPv4Address
from typing import TYPE_CHECKING
from requests.exceptions import ConnectionError as RequestsConnectionError

from mfd_common_libs import log_levels, add_logging_level

from .exceptions import OsdControllerException

if TYPE_CHECKING:
    from mfd_typing import MACAddress


logger = logging.getLogger(__name__)
add_logging_level(level_name="MODULE_DEBUG", level_value=log_levels.MODULE_DEBUG)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RefreshMode(Enum):
    """Available refresh modes."""

    ON_DEMAND = "ON_DEMAND"
    ONCE = "ONCE"
    ALWAYS = "ALWAYS"


class ActiveBootType(Enum):
    """Available active boot types."""

    DISKLESS = "DISKLESS"
    IMAGE_LOADER = "IMAGE_LOADER"
    ISO_AUTOMATIC = "ISO_AUTOMATIC"
    ISO_MANUAL = "ISO_MANUAL"


class OsType(Enum):
    """Available OS types."""

    DISKLESS = "diskless"
    IMAGE_LOADER = "image_loader"
    ISO = "iso"


ACTIVE_BOOT_TYPE_OS_MAP = {
    ActiveBootType.DISKLESS: "diskless_os_key",
    ActiveBootType.IMAGE_LOADER: "image_loader_os_key",
    ActiveBootType.ISO_AUTOMATIC: "iso_os_key",
    ActiveBootType.ISO_MANUAL: "iso_os_key",
}


class OsdController:
    """Class for controlling OSD."""

    def __init__(
        self,
        *,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        secured: bool | None = True,
        proxies: dict[str, str] | None = None,
        verify: bool = False,
    ) -> None:
        """
        Initialize controller.

        :param base_url: Base OSD portal URL
        :param username: Username for authorize
        :param password: Password for authorize
        :param secured: Flag for enabling https
        :param proxies: Use selected proxy when connecting to diskless. By default (None) uses OS env for connection.
        :param verify: Whether to verify the SSL certificate (default is False)
        :raises OsdControllerException: if ip address is not correct or if cannot connect with diskless
        """
        self._auth_details = username, password
        self.proxies = proxies
        self.verify = verify

        prefix = "https://" if secured else "http://"

        self._api_url = f"{prefix}{base_url}/v1/api/"
        error_message = f"Cannot establish connection with diskless {self._api_url}"

        try:
            correct_status_code = HTTPStatus.OK
            response = requests.get(
                f"{self._api_url}storage_satellite/diskless",
                auth=self._auth_details,
                proxies=self.proxies,
                verify=self.verify,
            )
            if response.status_code != correct_status_code:
                logger.log(log_levels.MODULE_DEBUG, msg=response.content)
                raise OsdControllerException(error_message)
        except RequestsConnectionError as e:
            raise OsdControllerException(error_message) from e

    def _normalize_mac(self, mac: "MACAddress | str") -> str:
        """
        Normalize MAC address to lowercase string.

        :param mac: MAC address
        :return: Normalized MAC address as lowercase string
        """
        return mac.lower() if isinstance(mac, str) else str(mac).lower()

    def does_host_exist(self, mac: "MACAddress | str") -> bool:
        """
        Check if host exists.

        :param mac: MAC address
        :return: boolean value indicating whether host exists or not
        :raises OsdControllerException: if response has incorrect status code
        """
        mac = self._normalize_mac(mac)
        correct_status_codes = {HTTPStatus.OK: True, HTTPStatus.NOT_FOUND: False}
        get_host_details_url = f"{self._api_url}host/{mac}"
        logger.log(
            log_levels.MODULE_DEBUG, msg=f"Sending GET request to OSD {self._api_url} for host information."
        )
        response = requests.get(get_host_details_url, auth=self._auth_details, proxies=self.proxies, verify=self.verify)
        if response.status_code in correct_status_codes:
            return correct_status_codes.get(response.status_code)
        else:
            raise OsdControllerException(f"OSD returned unknown code: {response.status_code}")

    def get_host_details(self, mac: "MACAddress | str") -> dict[str, str]:
        """
        Send GET request for showing specific host information.

        :param mac: MAC address
        :raises OsdControllerException: if response has incorrect structure or status code
        """
        mac = self._normalize_mac(mac)
        correct_status_code = HTTPStatus.OK
        get_host_details_url = f"{self._api_url}host/{mac}"
        logger.log(
            log_levels.MODULE_DEBUG, msg=f"Sending GET request to diskless {self._api_url} for host information."
        )
        response = requests.get(get_host_details_url, auth=self._auth_details, proxies=self.proxies, verify=self.verify)
        if response.status_code != correct_status_code:
            logger.log(log_levels.MODULE_DEBUG, msg=response.content)
            raise OsdControllerException(f"OSD returned unknown code: {response.status_code}")
        else:
            data = response.json()
            if isinstance(data, dict) and data.get("key").lower() == mac:  # check structure of response
                logger.log(log_levels.MODULE_DEBUG, msg=f"Received host '{mac}' information from OSD {self._api_url}")
                return data
            else:
                logger.log(log_levels.MODULE_DEBUG, msg=data)
                raise OsdControllerException("OSD response has got incorrect structure")

    def add_host(
        self,
        *,
        mac: "MACAddress | str",
        os: str,
        active_boot_type: ActiveBootType,
        refresh: RefreshMode,
        description: str | None = None,
    ) -> None:
        """
        Send POST request for adding host to OSD.

        :param mac: MAC address
        :param os: OS key (one from available on OSD) - depends on active boot type
        :param active_boot_type: Active boot type
        :param refresh: Refresh mode
        :param description: Optional description for host
        :raises OsdControllerException: if returned incorrect status code
        """
        mac = self._normalize_mac(mac)
        correct_status_code = HTTPStatus.OK
        add_host_url = f"{self._api_url}host"
        params = {
            "key": mac,
            ACTIVE_BOOT_TYPE_OS_MAP[active_boot_type]: os,
            "active_boot_type": active_boot_type.value,
            "refresh_mode": refresh.value,
        }
        if description:
            params["description"] = description
        logger.log(
            log_levels.MODULE_DEBUG,
            msg=f"Sending POST request to OSD {self._api_url} with params {params} for add host.",
        )
        response = requests.post(
            add_host_url, json=params, auth=self._auth_details, proxies=self.proxies, verify=self.verify
        )
        if response.status_code != correct_status_code:
            logger.log(log_levels.MODULE_DEBUG, msg=response.content)
            raise OsdControllerException(f"OSD returned unknown code: {response.status_code}")
        else:
            logger.log(log_levels.MODULE_DEBUG, msg=f"Added host {mac} to OSD {self._api_url}")

    def alter_host(
        self,
        *,
        mac: "MACAddress | str",
        diskless_os: str | None = None,
        imageloader_os: str | None = None,
        iso_os: str | None = None,
        active_boot_type: ActiveBootType | None = None,
        refresh: RefreshMode | None = None,
        description: str | None = None,
    ) -> None:
        """
        Change Host properties by sending PUT request.

        :param mac: MAC address
        :param diskless_os: Diskless OS key (one from available on OSD)
        :param imageloader_os: ImageLoader OS key (one from available on OSD)
        :param iso_os: ISO OS key (one from available on OSD)
        :param active_boot_type: Active boot type
        :param refresh: Refresh mode
        :param description: Description of the host
        :raises OsdControllerException: if returned unexpected status code
        """
        mac = self._normalize_mac(mac)
        correct_status_code = HTTPStatus.OK
        alter_host_url = f"{self._api_url}host/{mac}"
        params = {}
        if not any([diskless_os, imageloader_os, iso_os, active_boot_type, refresh, description]):
            raise OsdControllerException(f"Payload for altering host {mac} cannot be empty.")
        if diskless_os:
            params[ACTIVE_BOOT_TYPE_OS_MAP[ActiveBootType.DISKLESS]] = diskless_os
        if imageloader_os:
            params[ACTIVE_BOOT_TYPE_OS_MAP[ActiveBootType.IMAGE_LOADER]] = imageloader_os
        if iso_os:
            params[ACTIVE_BOOT_TYPE_OS_MAP[ActiveBootType.ISO_AUTOMATIC]] = iso_os
        if refresh:
            params["refresh_mode"] = refresh.value
        if description:
            params["description"] = description

        logger.log(
            log_levels.MODULE_DEBUG,
            msg=f"Sending PUT request to OSD {self._api_url} with params {params} for altering host.",
        )
        response = requests.put(
            alter_host_url, json=params, auth=self._auth_details, proxies=self.proxies, verify=self.verify
        )
        if response.status_code != correct_status_code:
            logger.log(log_levels.MODULE_DEBUG, msg=response.content)
            raise OsdControllerException(f"OSD returned unexpected status code: {response.status_code}")
        else:
            logger.log(log_levels.MODULE_DEBUG, msg=f"Host {mac} has been updated successfully.")

    def delete_host(self, *, mac: "MACAddress | str") -> None:
        """
        Send DELETE request for remove host from diskless.

        :param mac: MAC address
        :raises OsdControllerException: if returned incorrect status code
        """
        mac = self._normalize_mac(mac)
        correct_status_code = HTTPStatus.OK
        delete_host_url = f"{self._api_url}host/{mac}"
        logger.log(log_levels.MODULE_DEBUG, msg=f"Sending DELETE request to OSD {self._api_url} for remove host.")
        response = requests.delete(delete_host_url, auth=self._auth_details, proxies=self.proxies, verify=self.verify)
        if response.status_code != correct_status_code:
            logger.log(log_levels.MODULE_DEBUG, msg=response.content)
            raise OsdControllerException(f"OSD returned unknown code: {response.status_code}")
        else:
            logger.log(log_levels.MODULE_DEBUG, msg=f"Removed host {mac} from OSD {self._api_url}")

    def get_available_oses(self, mac: "MACAddress | str", os_type: OsType) -> list[str]:
        """
        Get sorted list of available OSes on OSD for host.

        :param mac: MAC address
        :param os_type: OS type - DISKLESS, IMAGE_LOADER, ISO
        :return: List of OSes
        :raises OsdControllerException: if returned incorrect status code
        """
        mac = self._normalize_mac(mac)
        correct_status_code = HTTPStatus.OK
        get_oses_url = f"{self._api_url}os/{os_type.value}/?host_filter={mac}"
        logger.log(log_levels.MODULE_DEBUG, msg=f"Sending GET request to OSD {self._api_url} for list of OSes.")
        response = requests.get(get_oses_url, auth=self._auth_details, proxies=self.proxies, verify=self.verify)
        if response.status_code != correct_status_code:
            logger.log(log_levels.MODULE_DEBUG, msg=response.content)
            raise OsdControllerException(f"OSD returned unknown code: {response.status_code}")
        else:
            data = response.json()
            if "objects" not in data or not all("key" in k for k in data["objects"]):
                logger.log(log_levels.MODULE_DEBUG, msg=data)
                raise OsdControllerException("OSD response has got incorrect structure")
            elif len(data["objects"]) == 0:
                logger.log(log_levels.MODULE_DEBUG, msg=f"No oses found for {mac} for given os_type")
                return []
            logger.log(log_levels.MODULE_DEBUG, msg=f"Received list of oses from OSD {self._api_url}")
            return sorted([image["key"] for image in data["objects"]])

    def get_host_ip(self, mac: "MACAddress | str") -> IPv4Address:
        """
        Get IP address of the host with the specific MAC address.

        :param mac: MAC address of the host
        :return: Retrieved IP address
        """
        ip = self.get_host_details(str(mac)).get("ip")
        return IPv4Address(ip)
