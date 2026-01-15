import logging
import sys
from typing import Any, Callable, List
import hid
import struct
import asyncio

from bleak import BleakScanner, BleakClient, BLEDevice

from bumble.device import Device, Peer, Advertisement, DeviceConfiguration
from bumble.transport import open_transport_or_link
from bumble.rfcomm import Client as RFCOMM_Client
from bumble.rfcomm import find_rfcomm_channel_with_uuid, find_rfcomm_channels, DLC
from bumble.core import (
    BT_BR_EDR_TRANSPORT,
    BT_LE_TRANSPORT,
    UUID,
    AdvertisingData,
    ConnectionError,
)
from bumble.hci import (
    Address,
    STATUS_SPEC,
    HCI_Command,
    HCI_Read_BD_ADDR_Command,
    HCI_Read_Local_Version_Information_Command,
    hci_vendor_command_op_code,
)
from bumble.colors import color
from bumble import hfp

from librace.constants import UuidTable

# Broadcom/Cypress vendor-specific HCI command to change BD address
HCI_VSC_WRITE_BD_ADDR_COMMAND = hci_vendor_command_op_code(0x01)  # 0xFC01
HCI_Command.register_commands(
    {"HCI_VSC_WRITE_BD_ADDR_COMMAND": HCI_VSC_WRITE_BD_ADDR_COMMAND}
)


@HCI_Command.command(
    fields=[("bd_addr", Address.parse_address)],
    return_parameters_fields=[("status", STATUS_SPEC)],
)
class HCI_VSC_Write_BD_ADDR_Command(HCI_Command):
    pass


class Transport(object):
    """This is the base class for the different transports (e.g., BLE, RFCOMM, USB, ...)"""

    async def setup(self, recv_fn: Callable):
        raise NotImplementedError()

    async def send(self, data: bytes):
        raise NotImplementedError()

    async def close(self):
        raise NotImplementedError()


class GATTBleakTransport(Transport):
    def __init__(self, addr: str, devices: List[str]):
        self.rx_char = None
        self.tx_char = None
        self.address = addr
        self.client = None
        self.recv_fn = None
        self.devices = devices
        self.device_class = None

    async def setup(self, recv_fn: Callable):
        """Setup GATT connection."""

        # already setup
        if self.client:
            return

        if self.address is None:
            self.address = await self._find_target_device()
            if self.address is None:
                sys.exit(1)

        self.client = BleakClient(self.address)
        await self.client.connect()

        logging.info(f"Connected to {self.address.name} ({self.address.address})")

        service_uuids = [
            UUID(self.client.services.services[s].uuid)
            for s in self.client.services.services
        ]

        if UuidTable.AIROHA_GATT_SERVICE_UUID in service_uuids:
            logging.info(
                color(
                    f"Found the Airoha RACE UUID {UuidTable.AIROHA_GATT_SERVICE_UUID}!",
                    "cyan",
                )
            )
            self.rx_char = UuidTable.AIROHA_GATT_RX_UUID
            self.tx_char = UuidTable.AIROHA_GATT_TX_UUID
            self.service = UuidTable.AIROHA_GATT_SERVICE_UUID
        elif UuidTable.SONY_GATT_SERVICE_UUID in service_uuids:
            logging.info(
                color(
                    f"Found the Sony RACE UUID {UuidTable.AIROHA_GATT_SERVICE_UUID}!",
                    "cyan",
                )
            )
            self.rx_char = UuidTable.SONY_GATT_RX_UUID
            self.tx_char = UuidTable.SONY_GATT_TX_UUID
            self.service = UuidTable.SONY_GATT_SERVICE_UUID
        else:
            logging.warning("No known RACE UUID found.")
            return

        self.recv_fn = recv_fn
        await self.client.start_notify(self.rx_char, self._recv_wrapper)

    async def send(self, data: bytes):
        if not self.client:
            logging.error("No bleak client.")
            return
        await self.client.write_gatt_char(self.tx_char, data)

    async def close(self):
        if self.client:
            await self.client.disconnect()

    async def _recv_wrapper(self, sender: Any, data: bytes):
        if self.recv_fn:
            self.recv_fn(data)

    def _device_filter(self, device: BLEDevice):
        if not device.name:
            return False

        # if we have a user-supplied list of devices, filter for them
        if self.devices:
            for d in self.devices:
                if d in device.name:
                    return True
        else:
            return True

    async def _find_target_device(self):
        logging.info("Scanning for BLE devices...")
        devices = await BleakScanner.discover()

        # filter for known names
        devices = list(filter(self._device_filter, devices))

        if len(devices) > 0:
            if len(devices) == 1:
                return devices[0]

            logging.info(f"Found {len(devices)} matching devices:")
            for i, device in enumerate(devices):
                logging.info(f"[{i}]: {device.name} ({device.address})")

            chosen = -1
            while chosen >= len(devices) or chosen < 0:
                chosen = int(input("Which one do you want to connect to?\n"))
            return devices[chosen]

        logging.info("No target device found.")
        return None


class BumbleTransport(Transport):
    """Generic Class for all Bumble based Transport. Does most of the Bumble and device handling"""

    def __init__(self, ctrl_dev: Device, address: str, authenticate: bool):
        self.ctrl_dev = ctrl_dev
        self.address = address
        self.connection = None
        self.t = None
        self.authenticate = authenticate
        self.device = None

        if authenticate:
            logging.warning(
                "Flag --authenticate is set. Will try to establish a pairing with the target device. If the device is already paired this might fail."
            )

    async def _initialize_device(self, classic: bool = False, le: bool = False):
        """Initialize the Bumble device with the given transport address."""
        self.t = await open_transport_or_link(self.ctrl_dev)
        # Ensure that Link Keys are stored in Bumble's LK storage
        config = DeviceConfiguration()
        config.keystore = "JsonKeyStore"
        config.address = Address.generate_static_address()
        config.name = "BumbleRace"
        self.device = Device.from_config_with_hci(config, self.t.source, self.t.sink)
        if classic:
            self.device.classic_enabled = True
        if le:
            self.device.le_enabled = True
        await self.device.power_on()
        logging.info("Device initialized.")

    async def change_bd_addr(self, new_addr: Address):
        """Change the BD address of the controller. Works only on Broadcom/Cypress controlelrs."""
        # Change BD address only when we have a Cypress or Broadcom Bluetooth controller
        response = await self.device.send_command(
            HCI_Read_Local_Version_Information_Command(), check_result=True
        )
        company_id = response.return_parameters.company_identifier
        # Broadcom is 0x000f
        # Cypress  is 0x0131
        if company_id in [0x000F, 0x0131]:
            await self.device.send_command(
                HCI_VSC_Write_BD_ADDR_Command(bd_addr=new_addr)
            )
            response = await self.device.send_command(HCI_Read_BD_ADDR_Command())
            check_addr = response.return_parameters.bd_addr
            if check_addr == new_addr:
                logging.info(f"Changed BD address to {check_addr}")
                return True
            else:
                logging.error(
                    f"Changing BD address failed, address is now {check_addr}"
                )
                return False
        else:
            logging.error(
                f"Unknown Bluetooth Controller vendor {hex(company_id)}. Can't change BD address."
            )
            return False

    async def close(self):
        if self.connection:
            # If the device disconnects before us, this leads to an exception. Here we don't care. We just want a clean exit.
            try:
                await self.connection.disconnect()
            except:  # noqa: E722
                pass
        if self.device:
            await self.device.power_off()
        if self.t:
            await self.t.close()


class GATTBumbleChecker(BumbleTransport):
    """This class is used to identify a user's device and check for the RACE GATT UUID(s)"""

    def __init__(self, ctrl_dev: str, addr: str, scan_time: int = 5):
        super().__init__(ctrl_dev, addr, False)
        self.rx_char = None
        self.tx_char = None
        self.service = None
        self.client = None
        self.recv_fn = None
        self.device_class = None
        self.name = None
        self.scan_time = scan_time

    async def setup(self, recv_fn: Callable):
        # already setup
        if self.client:
            return

        # Initialize the Bumble device
        await self._initialize_device(le=True)
        if not self.device:
            logging.error("Device could not be created.")
            return

    async def scan_devices(self):
        device_dict = {}

        def on_adv(adv: Advertisement):
            ln = adv.data.get(AdvertisingData.COMPLETE_LOCAL_NAME)
            if ln:
                logging.debug(f"Found device {ln} - {adv.address}")
                device_dict[adv.address] = ln

        self.device.on("advertisement", on_adv)

        # Start scanning and do so for a defined number of seconds
        await self.device.start_scanning(True, filter_duplicates=True)
        await asyncio.sleep(self.scan_time)
        self.device.remove_listener("advertisement", on_adv)
        await self.device.stop_scanning()

        devices = list(device_dict.items())
        if len(devices) > 0:
            logging.info(f"Found {len(devices)} devices:")
            for i, (address, name) in enumerate(devices):
                logging.info(f"[{i}]: {name} ({address})")
            logging.info("[X]: None of these devices is mine.")

            chosen = -1
            logging.info(color("Which one of these is yours? ", "cyan"))
            chosen = input("")
            if chosen.lower() == "x":
                return False
            else:
                chosen = int(chosen)
                return devices[chosen]
        else:
            logging.warning("No BLE devices found. Try to get closer to your device?")

    async def check_UUIDs(self, address: str):
        self.address = address

        self.connection = await self.device.connect(
            self.address, transport=BT_LE_TRANSPORT
        )
        if not self.connection:
            logging.error("Connection could not be established.")
            return

        self.client = Peer(self.connection).gatt_client

        await self.client.discover_services()

        logging.info(
            f"Found {len(self.client.services)} services. Checking for RACE UUIDs"
        )
        service_uuids = [s.uuid for s in self.client.services]

        if str(UuidTable.AIROHA_GATT_SERVICE_UUID) in service_uuids:
            logging.info(
                color(
                    f"Found the Airoha RACE UUID {UuidTable.AIROHA_GATT_SERVICE_UUID}!",
                    "cyan",
                )
            )
            return True
        elif str(UuidTable.SONY_GATT_SERVICE_UUID) in service_uuids:
            logging.info(
                color(
                    f"Found the Sony RACE UUID {UuidTable.AIROHA_GATT_SERVICE_UUID}!",
                    "cyan",
                )
            )
            return True
        else:
            logging.warning("No known RACE UUID found.")
        return False


class RFCOMMBumbleChecker(BumbleTransport):
    def __init__(self, ctrl_dev: str, address: str, authenticate: bool):
        super().__init__(ctrl_dev, address, authenticate)
        self.device = None
        self.rfcomm_session = None
        self.connection = None
        self.device_class = None

    async def setup(self):
        # already setup
        if self.device:
            return

        # Initialize the Bumble device
        await self._initialize_device(classic=True)
        if not self.device:
            logging.error("Device could not be created.")
            return

    async def check_UUIDs(self):
        # Connect to the remote device
        self.connection = await self.device.connect(
            self.address, transport=BT_BR_EDR_TRANSPORT
        )
        await self.connection.request_remote_name()

        channels = await find_rfcomm_channels(self.connection)
        for chn in channels:
            uuid = RFCOMMTransport._matches_any_known_uuid(channels[chn])
            if uuid:
                return uuid
        return None

    async def check_auth_vuln(self):
        """Check Classic authentication issue by connecting via HfP. This makes it independant of whether RACE is exposed via RFCOMM."""

        try:
            if not (hfp_record := await hfp.find_hf_sdp_record(self.connection)):
                logging.warning("HfP Service not found.")
                return False

            channel, _, _ = hfp_record

            rfcomm_client = RFCOMM_Client(self.connection)
            rfcomm_mux = await rfcomm_client.start()

            session = await rfcomm_mux.open_dlc(channel)
            if session:
                await rfcomm_mux.disconnect()
                return True
            return False
        except asyncio.CancelledError as e:
            logging.warning(f"Error connecting to device via HfP ({e}).")
            return False
        except ConnectionError as e:
            logging.warning(f"Error connecting to device via HfP ({e}).")
            return False
        except Exception as e:
            logging.warning(
                f"Error while checking Bluetooth Classic authentication ({e})."
            )
            return False
        finally:
            await rfcomm_client.shutdown()


class GATTBumbleTransport(BumbleTransport):
    def __init__(
        self,
        ctrl_dev: str,
        addr: str,
        devices: List[str],
        authenticate: bool,
        scan_time: int = 2,
    ):
        super().__init__(ctrl_dev, addr, authenticate)
        self.rx_char = None
        self.tx_char = None
        self.service = None
        self.client = None
        self.recv_fn = None
        self.devices = devices
        self.device_class = None
        self.name = None
        self.scan_time = scan_time

    async def setup(self, recv_fn: Callable):
        """Setup GATT connection."""

        # already setup
        if self.client:
            # The only thing we might want to update is the recv handler
            self.recv_fn = recv_fn
            return

        # Initialize the Bumble device
        await self._initialize_device(le=True)
        if not self.device:
            logging.error("Device could not be created.")
            return

        if self.address is None:
            (self.address, self.name) = await self._find_target_device()
            if self.address is None:
                sys.exit(1)

        # Connect to the remote device
        self.connection = await self.device.connect(
            self.address, transport=BT_LE_TRANSPORT
        )
        if not self.connection:
            logging.error("Connection could not be established.")
            return

        if self.authenticate:
            await self.connection.authenticate()

        if self.name is None:
            self.name = await self.connection.request_remote_name()

        await self.setup_gatt(recv_fn)

    async def setup_gatt(self, recv_fn: Callable):
        """Only set up the GATT part of this transport. Requires a connection."""

        if not self.connection:
            return False

        self.client = Peer(self.connection).gatt_client

        mtu = await self.client.request_mtu(256)
        logging.info(f"Negotiated GATT MTU to {mtu}.")

        await self.client.discover_services(
            [UuidTable.AIROHA_GATT_SERVICE_UUID, UuidTable.SONY_GATT_SERVICE_UUID]
        )
        for service in self.client.services:
            await service.discover_characteristics()

        service_uuids = [s.uuid for s in self.client.services]

        if UuidTable.AIROHA_GATT_SERVICE_UUID in service_uuids:
            logging.info(
                color(
                    f"Found the Airoha RACE UUID {UuidTable.AIROHA_GATT_SERVICE_UUID}!",
                    "cyan",
                )
            )
            self.rx_char = UuidTable.AIROHA_GATT_RX_UUID
            self.tx_char = UuidTable.AIROHA_GATT_TX_UUID
            self.service = UuidTable.AIROHA_GATT_SERVICE_UUID
        elif UuidTable.SONY_GATT_SERVICE_UUID in service_uuids:
            logging.info(
                color(
                    f"Found the Sony RACE UUID {UuidTable.AIROHA_GATT_SERVICE_UUID}!",
                    "cyan",
                )
            )
            self.rx_char = UuidTable.SONY_GATT_RX_UUID
            self.tx_char = UuidTable.SONY_GATT_TX_UUID
            self.service = UuidTable.SONY_GATT_SERVICE_UUID
        else:
            logging.warning("No known RACE UUID found.")
            return

        # get_characteristics_by_uuid returns a list; we pick the first.
        tx_chars = self.client.get_characteristics_by_uuid(self.tx_char)
        if not tx_chars:
            logging.error(f"Write characteristic {self.tx_char} not found!")
            return
        self.tx_char_handle = tx_chars[0]

        # Find the characteristic we want to subscribe to notifications.
        rx_chars = self.client.get_characteristics_by_uuid(self.rx_char)
        if not rx_chars:
            logging.error(f"Write characteristic {self.tx_char} not found!")
            return
        self.rx_char_handle = rx_chars[0]

        self.recv_fn = recv_fn

        # Subscribe to notifications on the notify characteristic.
        await self.client.subscribe(
            self.rx_char_handle, self._recv_internal, prefer_notify=True
        )

    async def send(self, data: bytes):
        if not self.client:
            logging.error("No GATT client, cannot send.")
            return
        await self.client.write_value(self.tx_char_handle, data, with_response=True)

    def _recv_internal(self, data: bytes):
        if self.recv_fn:
            self.recv_fn(data)

    async def _recv_wrapper(self, data: bytes):
        if self.recv_fn:
            self.recv_fn(data)

    def matches(self, matchers: List[str], device: str):
        for m in matchers:
            if m in device:
                return True
        return False

    async def _find_target_device(self):
        logging.info("Scanning for BLE devices...")

        device_dict = {}

        def on_adv(adv: Advertisement):
            ln = adv.data.get(AdvertisingData.COMPLETE_LOCAL_NAME)
            if ln:
                # if we have a user-supplied list of devices, filter for them
                if self.devices:
                    # for some reason bumble seems to have LE_ prefixes while bleak doesn't
                    # if ln in self.devices or ln.strip("LE_") in self.devices:
                    if self.matches(self.devices, ln):
                        logging.info(f"Found device {ln} - {adv.address}")
                        device_dict[adv.address] = ln
                else:
                    device_dict[adv.address] = ln

        self.device.on("advertisement", on_adv)

        await self.device.start_scanning(True, filter_duplicates=True)
        while len(device_dict) == 0:
            await asyncio.sleep(self.scan_time)
        self.device.remove_listener("advertisement", on_adv)
        await self.device.stop_scanning()

        devices = list(device_dict.items())
        if len(devices) > 0:
            if len(devices) == 1:
                address, name = devices[0]
                return (address, name)

            logging.info(f"Found {len(devices)} matching devices:")
            for i, (address, name) in enumerate(devices):
                logging.info(f"[{i}]: {name} ({address})")

            chosen = -1
            while chosen >= len(devices) or chosen < 0:
                chosen = int(input("Which one do you want to connect to?\n"))
            return devices[chosen]

        logging.warning("No target device found.")
        return None


class RFCOMMTransport(BumbleTransport):
    def __init__(
        self, ctrl_dev: str, address: str, authenticate: bool, uuid: UUID = None
    ):
        super().__init__(ctrl_dev, address, authenticate)
        self.device = None
        self.rfcomm_session = None
        self.connection = None
        self.device_class = None
        self.uuid = uuid

    @staticmethod
    def _matches_any_known_uuid(uuid_lst: List[UUID]):
        vendor = ""
        for uuid in uuid_lst:
            if uuid == UuidTable.AIROHA_SPP_UUID:
                vendor = "Airoha"
            elif uuid == UuidTable.BEYER_SPP_UUID:
                vendor = "Beyerdynamic"
            elif uuid == UuidTable.BOSE_SPP_UUID_SERVICE:
                vendor = "Bose"
            elif uuid == UuidTable.SONY_SPP_UUID:
                vendor = "SONY"
            elif uuid == UuidTable.COMMON_SPP_UUID:
                vendor = "Common"
            if vendor != "":
                logging.info(
                    color(f"Found RACE UUID {uuid} for vendor {vendor}", "cyan")
                )
                return uuid
        return None

    async def setup(self, recv_fn: Callable):
        """Establish an RFCOMM Bluetooth connection."""

        # already setup
        if self.device:
            # The only thing we might want to update is the recv handler
            self.recv_fn = recv_fn
            if self.rfcomm_session:
                self.rfcomm_session.sink = self.recv_fn
            return

        # Initialize the Bumble device
        await self._initialize_device(classic=True)
        if not self.device:
            logging.error("Device could not be created.")
            return

        try:
            # Connect to the remote device
            self.connection = await self.device.connect(
                self.address, transport=BT_BR_EDR_TRANSPORT
            )
            await self.connection.request_remote_name()

            if self.authenticate:
                await self.connection.authenticate()

            # a user can supply a UUID
            if not self.uuid:
                channels = await find_rfcomm_channels(self.connection)
                for chn in channels:
                    uuid = RFCOMMTransport._matches_any_known_uuid(channels[chn])
                    if uuid:
                        self.uuid = uuid

            # If we still have no UUID we have to stop here
            if not self.uuid:
                logging.error("Unable to find RACE RFCOMM UUID.")
                return

            # Find RACE channel based on its UUID
            channel = await find_rfcomm_channel_with_uuid(self.connection, self.uuid)
            if channel is None:
                logging.error("Channel not found.")
                return
            logging.info(f"Channel found: {int(channel)}")

            # Establish an RFCOMM session
            rfcomm_client = RFCOMM_Client(self.connection)
            rfcomm_mux = await rfcomm_client.start()
            self.rfcomm_session = await rfcomm_mux.open_dlc(channel)
            logging.info(f"Connected to {self.address} on channel {channel}")

            self.rfcomm_session.sink = recv_fn

        except Exception as e:
            logging.error("Connection error:", e)
            return

    async def send(self, data: bytes):
        if not self.rfcomm_session:
            logging.error("RFCOMM session is not established.")
            return
        self.rfcomm_session.write(data)

    async def close(self):
        # Close RFCOMM session and then disconnect and power off device.
        # Only disconnect if we are still connected.
        if self.rfcomm_session and self.rfcomm_session.state == DLC.State.CONNECTED:
            await self.rfcomm_session.disconnect()
        await super().close()


class USBHIDTransport(Transport):
    USB_RACE_PREFIX = b"\x06"
    # bigger sizes will lead to errors (empirical)
    REPORT_BUFFER_SIZE = 62
    RACE_HID_REPORT_ID = 7

    def __init__(self, device_str: str):
        self.device = None
        self.recv_fn = None
        self.device_name = None

        # try to parse USB device if given
        self.vid = None
        self.pid = None
        self.path = None
        if device_str:
            try:
                (self.vid, self.pid) = device_str.split(":")
                self.vid = int(self.vid, 16)
                self.pid = int(self.pid, 16)
            except ValueError:
                logging.error(
                    f"Unknown USB device {device_str}. Please provice the device as VID:PID pair."
                )

    async def setup(self, recv_fn: Callable):
        if self.device is None:
            devices = hid.enumerate()
            # filter for only USB HID devices
            devices = list(
                filter(
                    lambda x: x["bus_type"] == 1 and x["usage_page"] == 0xFF13, devices
                )
            )
            # only one entry per vid/pid pair is required
            devices = self._filter_unique_vid_pid(devices)

            if self.vid is None and self.pid is None:
                device = self._choose_from_list(devices)

                self.vid = device["vendor_id"]
                self.pid = device["product_id"]
                self.path = device["path"]
            elif self.path is None:
                devices = list(
                    filter(
                        lambda x: (x["vendor_id"], x["product_id"])
                        == (self.vid, self.pid),
                        devices,
                    )
                )
                self.path = devices[0]["path"]

            self.device = hid.device()
            logging.info(f"Opening {self.vid:04x}:{self.pid:04x} {self.path}.")
            self.device.open_path(self.path)
            self.device_name = self.device.get_product_string()
            logging.info(f"Using device {self.device_name} as device.")

        self.recv_fn = recv_fn

    async def send(self, data: bytes):
        if self.device is None:
            logging.error("No USBHID device connected")
            return

        self._flush_hid_buffer()
        outbuf = USBHIDTransport.USB_RACE_PREFIX + struct.pack("<H", len(data)) + data
        self.device.write(outbuf)

        if self.recv_fn:
            # first, receive until we get some responses
            (response, length) = self._read_report()
            while length == 0:
                (response, length) = self._read_report()
            # then receive until we get empty responses
            while length > 0:
                if response[0] == 0x07:
                    self.recv_fn(response[3 : 3 + length])
                (response, length) = self._read_report()

    async def close(self):
        if self.device:
            self.device.close()

    def _read_report(self):
        response = self.device.get_input_report(
            USBHIDTransport.RACE_HID_REPORT_ID, USBHIDTransport.REPORT_BUFFER_SIZE
        )
        response = bytes(response)
        length = struct.unpack("<H", response[1:3])[0]
        return (response, length)

    def _flush_hid_buffer(self):
        """Read and discard any leftover HID reports to clear the buffer."""
        for _ in range(3):
            (response, _) = self._read_report()
            if response and response[0] == 0x07:
                pass
            else:
                break

    def _filter_unique_vid_pid(self, devices: List[str]):
        seen = set()
        unique_devices = []
        for device in devices:
            pair = (device["vendor_id"], device["product_id"])
            if pair not in seen:
                seen.add(pair)
                unique_devices.append(device)
        return unique_devices

    def _choose_from_list(self, options: List[str]):
        logging.info("Choose USB HID device:")
        for idx, option in enumerate(options, start=1):
            n = option["product_string"]
            vid = hex(option["vendor_id"])
            pid = hex(option["product_id"])
            logging.info(f"[{idx}]: {n} (vid={vid}, pid={pid})")

        while True:
            try:
                choice = int(input("Enter the number of your choice: "))
                if 1 <= choice <= len(options):
                    return options[choice - 1]
                else:
                    logging.info(f"Please enter a number between 1 and {len(options)}.")
            except ValueError:
                logging.error("Invalid input. Please enter a number.")
