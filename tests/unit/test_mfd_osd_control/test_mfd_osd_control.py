# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: MIT
"""Tests for `mfd_osd_control` package."""

from http import HTTPStatus
import pytest

from ipaddress import IPv4Address

from mfd_osd_control import OsdController, RefreshMode, ActiveBootType, OsType
from mfd_osd_control.exceptions import OsdControllerException
from mfd_osd_control.mfd_osd_control import ACTIVE_BOOT_TYPE_OS_MAP
from mfd_typing import MACAddress


class TestMfdOsdControl:
    @pytest.fixture()
    def controller(self, get_mock):
        return OsdController(
            base_url="osd.com", username="user", password="pass", secured=False, proxies=None
        )

    @pytest.fixture()
    def get_mock(self, mocker):
        mock_response = mocker.Mock()
        mock_response.status_code = HTTPStatus.OK
        mock_get = mocker.Mock(return_value=mock_response)
        mocker.patch("requests.get", new=mock_get)
        return mock_get

    @pytest.fixture()
    def post_mock(self, mocker):
        mock_response = mocker.Mock()
        mock_post = mocker.Mock(return_value=mock_response)
        mocker.patch("requests.post", new=mock_post)
        return mock_post

    @pytest.fixture()
    def put_mock(self, mocker):
        mock_response = mocker.Mock()
        mock_put = mocker.Mock(return_value=mock_response)
        mocker.patch("requests.put", new=mock_put)
        return mock_put

    @pytest.fixture()
    def delete_mock(self, mocker):
        mock_response = mocker.Mock()
        mock_delete = mocker.Mock(return_value=mock_response)
        mocker.patch("requests.delete", new=mock_delete)
        return mock_delete

    @pytest.mark.parametrize("secured_flag, value", [(True, "https://"), (False, "http://")])
    def test_secured(self, get_mock, secured_flag, value):
        assert OsdController(
            base_url="osd.com", username="user", password="pass", secured=secured_flag, proxies=None
        )._api_url.startswith(value)

    @pytest.mark.parametrize("ip_address, result", [("osd.com", "osd.com")])
    def test_test_connection(self, get_mock, ip_address, result):
        controller = OsdController(base_url=ip_address, username="user", password="pass", secured=True, proxies=None)
        get_mock.assert_called_with(
            f"https://{result}/v1/api/storage_satellite/diskless",
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    @pytest.mark.parametrize("ip_address, result", [("osd.com", "osd.com")])
    def test_test_connection_with_proxy(self, get_mock, ip_address, result):
        proxy = {"https": ""}
        OsdController(base_url=ip_address, username="user", password="pass", secured=True, proxies=proxy)
        get_mock.assert_called_with(
            f"https://{result}/v1/api/storage_satellite/diskless", auth=("user", "pass"), proxies=proxy, verify=False
        )

    def test_test_connection_failure(self, get_mock):
        get_mock().status_code = 201
        with pytest.raises(OsdControllerException):
            OsdController(base_url="osd.com", username="user", password="pass", secured=True, proxies=None)

    @pytest.mark.parametrize("status_code, expected_value", [(HTTPStatus.OK, True), (HTTPStatus.NOT_FOUND, False)])
    def test_does_host_exist(self, get_mock, controller, status_code, expected_value):
        get_mock().status_code = status_code
        assert controller.does_host_exist(mac="00:11:22:AA:BB:CC") == expected_value

    def test_does_host_exist_failure(self, get_mock, controller):
        get_mock().status_code = 500
        with pytest.raises(OsdControllerException):
            controller.does_host_exist(mac="00:11:22:AA:BB:CC")

    def test_get_host_details(self, get_mock, mocker, controller):
        data = {"mac": "00:11:22:AA:BB:CC"}
        json_output = {
            "description": None,
            "hw_profile": None,
            "last_diskless_boot": "2021-09-28T11:02:50.875280",
            "key": data["mac"],
            "os": "RHEL",
            "refresh_mode": "always",
        }
        get_mock().status_code = HTTPStatus.OK
        get_mock().json = mocker.Mock(return_value=json_output)
        assert controller.get_host_details(mac=data["mac"]) == json_output
        get_mock.assert_called_with(
            f"http://osd.com/v1/api/host/{data['mac'].lower()}",
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    def test_get_host_details_failure(self, get_mock, controller):
        get_mock().status_code = HTTPStatus.NOT_FOUND
        data = {"mac": "00:11:22:AA:BB:CC"}
        with pytest.raises(OsdControllerException) as e:
            controller.get_host_details(mac=data["mac"])
        assert f"OSD returned unknown code: {get_mock().status_code}" in str(e.value)

    def test_get_host_details_wrong_structure(self, get_mock, controller):
        data = {"mac": "00:11:22:AA:BB:CC"}
        get_mock().status_code = HTTPStatus.OK
        with pytest.raises(OsdControllerException):
            controller.get_host_details(mac=data["mac"])

    def test_add_host(self, post_mock, controller):
        post_mock().status_code = HTTPStatus.OK
        for boot_type in ActiveBootType:
            data = {
                "mac": "00:11:22:AA:BB:CC",
                "os": "RHEL",
                "active_boot_type": boot_type,
                "refresh": RefreshMode.ONCE,
            }
            params = {
                "key": "00:11:22:aa:bb:cc",
                ACTIVE_BOOT_TYPE_OS_MAP[boot_type]: "RHEL",
                "active_boot_type": boot_type.value,
                "refresh_mode": RefreshMode.ONCE.value,
            }
            controller.add_host(
                mac=data["mac"], os=data["os"], active_boot_type=data["active_boot_type"], refresh=data["refresh"]
            )
            post_mock.assert_called_with(
                "http://osd.com/v1/api/host",
                json=params,
                auth=("user", "pass"),
                proxies=controller.proxies,
                verify=False,
            )

    def test_add_host_failure(self, post_mock, controller):
        post_mock().status_code = HTTPStatus.NOT_FOUND
        data = {
            "mac": "00:11:22:AA:BB:CC",
            "os": "RHEL",
            "active_boot_type": ActiveBootType.DISKLESS,
            "refresh": RefreshMode.ONCE,
        }
        with pytest.raises(OsdControllerException):
            controller.add_host(
                mac=data["mac"], os=data["os"], active_boot_type=data["active_boot_type"], refresh=data["refresh"]
            )

    def test_alter_host_os_in_payload_only(self, put_mock, controller):
        put_mock().status_code = HTTPStatus.OK
        data = {"mac": "00:11:22:AA:BB:CC", "os": "RHEL", "refresh": RefreshMode.ONCE}
        params = {"diskless_os_key": "RHEL"}
        controller.alter_host(mac=data["mac"], diskless_os=data["os"])
        put_mock.assert_called_with(
            f"http://osd.com/v1/api/host/{data['mac'].lower()}",
            json=params,
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    def test_alter_host_description_in_payload_only(self, put_mock, controller):
        put_mock().status_code = HTTPStatus.OK
        data = {"mac": "00:11:22:AA:BB:CC"}
        params = {"description": "foo"}
        controller.alter_host(mac=data["mac"], description="foo")
        put_mock.assert_called_with(
            f"http://osd.com/v1/api/host/{data['mac'].lower()}",
            json=params,
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    def test_alter_host_refresh_in_payload_only(self, put_mock, controller):
        put_mock().status_code = HTTPStatus.OK
        data = {"mac": "00:11:22:AA:BB:CC"}
        params = {"refresh_mode": "ALWAYS"}
        controller.alter_host(mac=data["mac"], refresh=RefreshMode.ALWAYS)
        put_mock.assert_called_with(
            f"http://osd.com/v1/api/host/{data['mac'].lower()}",
            json=params,
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    def test_alter_host_os_failure(self, put_mock, controller):
        put_mock().status_code = HTTPStatus.NOT_FOUND
        data = {"mac": "00:11:22:AA:BB:CC", "os": "RHEL", "refresh": RefreshMode.ALWAYS, "description": "foo"}
        with pytest.raises(OsdControllerException):
            controller.alter_host(
                mac=data["mac"], diskless_os=data["os"], refresh=data["refresh"], description=data["description"]
            )

    def test_delete_host(self, delete_mock, controller):
        delete_mock().status_code = HTTPStatus.OK
        data = {"mac": "00:11:22:AA:BB:CC"}
        controller.delete_host(mac=data["mac"])
        delete_mock.assert_called_with(
            f"http://osd.com/v1/api/host/{data['mac'].lower()}",
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    def test_delete_host_failure(self, delete_mock, controller):
        delete_mock().status_code = HTTPStatus.NOT_FOUND
        data = {"mac": "00:11:22:AA:BB:CC", "os": "RHEL"}
        with pytest.raises(OsdControllerException):
            controller.delete_host(mac=data["mac"])

    def test_get_available_oses(self, controller, mocker, get_mock):
        list_of_oses = ["RHEL", "Windows"]
        json_output = {
            "num_results": 30,
            "objects": [
                {"description": None, "key": "Windows", "path": "Linux/SLES11SP4", "script": "SLES11"},
                {"description": None, "key": "RHEL", "path": "Linux/RHEL73", "script": "RHEL"},
            ],
            "page": 1,
            "total_pages": 1,
        }
        get_mock().status_code = HTTPStatus.OK
        get_mock().json = mocker.Mock(return_value=json_output)
        assert controller.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.DISKLESS) == list_of_oses
        get_mock.assert_called_with(
            "http://osd.com/v1/api/os/diskless/?host_filter=00:11:22:aa:bb:cc",
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )
        assert controller.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.IMAGE_LOADER) == list_of_oses
        get_mock.assert_called_with(
            "http://osd.com/v1/api/os/image_loader/?host_filter=00:11:22:aa:bb:cc",
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )
        assert controller.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.ISO) == list_of_oses
        get_mock.assert_called_with(
            "http://osd.com/v1/api/os/iso/?host_filter=00:11:22:aa:bb:cc",
            auth=("user", "pass"),
            proxies=controller.proxies,
            verify=False,
        )

    def test_get_available_oses_wrong_structure(self, controller, mocker, get_mock):
        json_output = {
            "num_results": 30,
            "obj": [
                {"description": None, "name": "Windows", "path": "Linux/SLES11SP4", "script": "SLES11"},
                {"description": None, "name": "RHEL", "path": "Linux/RHEL73", "script": "RHEL"},
            ],
            "page": 1,
            "total_pages": 1,
        }
        get_mock().status_code = HTTPStatus.OK
        get_mock().json = mocker.Mock(return_value=json_output)
        with pytest.raises(OsdControllerException):
            controller.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.DISKLESS)

    def test_get_available_oses_wrong_response(self, controller, get_mock):
        get_mock().status_code = HTTPStatus.NOT_FOUND
        with pytest.raises(OsdControllerException):
            controller.get_available_oses(mac="00:11:22:AA:BB:CC", os_type=OsType.DISKLESS)

    @pytest.mark.parametrize("mac", (MACAddress("00:11:22:AA:BB:CC"), "11:22:33:44:55:DD"))
    def test_get_host_ip(self, mac, get_mock, mocker, controller):
        json_output = {
            "description": None,
            "hw_profile": None,
            "last_diskless_boot": "2021-09-28T11:02:50.875280",
            "key": str(mac),
            "ip": "10.10.10.10",
            "os": "RHEL",
            "refresh_mode": "always",
        }
        get_mock().status_code = HTTPStatus.OK
        get_mock().json = mocker.Mock(return_value=json_output)
        assert controller.get_host_ip(mac=mac) == IPv4Address("10.10.10.10")
