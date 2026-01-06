"""RACE protocol memory/flash dumper classes.

This module provides classes for dumping RAM and Flash memory from
devices using the RACE protocol.
"""
import asyncio
import io
import logging
from typing import Callable, Optional

from tqdm import tqdm
from hexdump import hexdump

from librace.race import RACE
from librace.constants import RaceId
from librace.packets import (
    RaceHeader,
    RacePacket,
    ReadFlashPage,
    ReadFlashPageResponse,
    ReadAddress,
    ReadAddressResponse,
)


class RACEDumper:
    """Base class for RACE protocol memory dumpers.

    Subclasses must set the following attributes:
        r: RACE instance for communication
        start: Starting address to dump
        size: Number of bytes to dump
        unit_size: Size of each read unit (e.g., 4 for words, 256 for pages)
        unit: Human-readable unit name (e.g., "word", "page")
        desc: Description of what's being dumped (e.g., "RAM", "Flash")
        verb: Action verb (e.g., "Dumping")
        packet_prep: Callable that creates a packet for a given address
    """

    def __init__(self, progress: bool):
        """Initialize the dumper.

        Args:
            progress: Whether to show a progress bar during dump.
        """
        self.stop_event = asyncio.Event()
        self.outbuf = b""
        self.progress = progress
        self.had_errors = False
        # These are set by subclasses or in dump()
        self.r: RACE
        self.start: int = 0
        self.size: int = 0
        self.fd: Optional[io.IOBase] = None
        self.unit_size: int = 0
        self.unit: str = ""
        self.desc: str = ""
        self.verb: str = ""
        self.packet_prep: Callable[[int], RacePacket]

    async def dump(
        self,
        addr: Optional[int] = None,
        size: Optional[int] = None,
        fd: Optional[io.IOBase] = None
    ) -> bytes:
        """Dump memory from the target device.

        Args:
            addr: Optional starting address (overrides self.start).
            size: Optional size to dump (overrides self.size).
            fd: Optional file descriptor to write data to.

        Returns:
            The dumped data as bytes.
        """
        await self.r.setup(self.recv)

        if addr is not None and size is not None:
            self.start = addr
            self.size = size

        self.fd = fd

        # Calculate total units for progress bar
        total_units = self.size // self.unit_size

        if self.progress:
            with tqdm(
                total=total_units,
                desc=f"{self.verb} {self.desc}",
                unit=self.unit
            ) as pbar:
                address = self.start
                while address < self.start + self.size:
                    race_packet = self.packet_prep(address)
                    await self.send(race_packet)

                    # Wait for response before proceeding to the next page
                    await self.await_response()

                    # Update progress bar by one unit
                    pbar.update(1)
                    address += self.unit_size
            if self.had_errors:
                logging.warning(
                    "%s dump completed with errors (some pages failed).", self.desc)
            else:
                logging.info("%s dump completed successfully.", self.desc)
        else:
            address = self.start
            while address < self.start + self.size:
                race_packet = self.packet_prep(address)
                logging.debug(
                    "Sending %s/%s", hex(address), hex(self.start + self.size))
                logging.debug("\n%s", hexdump(race_packet.pack(), 'return'))
                await self.send(race_packet)

                # Wait for response before proceeding to the next page
                await self.await_response()

                address += self.unit_size

        result = self.outbuf
        self.outbuf = b""
        return result

    async def send(self, race_packet: RacePacket):
        """Send a RACE packet to the device."""
        await self.r.send(race_packet)

    def recv(self, data: bytes):
        """Handle received data from the device."""
        if not self.progress:
            logging.debug("Received response:")
            logging.debug("\n%s", hexdump(data, 'return'))
        unpacked = self._unpack(data)
        # Only append data if we got valid bytes (not None from errors)
        if unpacked is not None and isinstance(unpacked, bytes):
            # Write to the open file handle
            if self.fd:
                self.fd.write(unpacked)
                self.fd.flush()
            self.outbuf += unpacked
        elif unpacked is None:
            # Track that we had an error (don't append garbage)
            self.had_errors = True

        # Signal main loop to proceed regardless
        self.stop_event.set()

    def _unpack(self, data: bytes) -> Optional[bytes]:
        """Unpack received data. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement _unpack")

    async def await_response(self):
        """Wait for a response from the device."""
        await self.stop_event.wait()
        self.stop_event.clear()


class RACERAMDumper(RACEDumper):
    """Dumper for reading RAM via RACE protocol."""

    def __init__(self, r: RACE, start: int, size: int, progress: bool = True):
        """Initialize RAM dumper.

        Args:
            r: RACE instance for communication.
            start: Starting RAM address.
            size: Number of bytes to dump.
            progress: Whether to show progress bar.
        """
        super().__init__(progress)
        self.r = r
        self.start = start
        self.size = size
        self.unit_size = 0x4
        self.unit = "word"
        self.desc = "RAM"
        self.verb = "Dumping"
        self.packet_prep = ReadAddress

    def _unpack(self, data: bytes) -> Optional[bytes]:
        """Unpack RAM read response."""
        race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])

        if race_header.id == RaceId.RACE_READ_ADDRESS:
            packet = ReadAddressResponse.unpack(data)
            if packet.return_code != 0:
                logging.error(
                    "ERROR while reading at address %#x. Result: %d",
                    packet.page_address, packet.return_code
                )
                # Return None to indicate read failure - don't return garbage
                return None
            return packet.page_data
        # We got some unexpected packet
        packet = RacePacket.unpack(data)
        logging.error(
            "ERROR got an unexpected packet with ID %#x and payload:",
            packet.header.id
        )
        hexdump(packet.payload)
        return None


class RACEFlashDumper(RACEDumper):
    """Dumper for reading Flash via RACE protocol."""

    def __init__(self, r: RACE, start: int, size: int, progress: bool = True):
        """Initialize Flash dumper.

        Args:
            r: RACE instance for communication.
            start: Starting Flash address.
            size: Number of bytes to dump.
            progress: Whether to show progress bar.
        """
        super().__init__(progress)
        self.r = r
        self.start = start
        self.size = size
        self.unit_size = 0x100
        self.unit = "page"
        self.desc = "Flash"
        self.verb = "Dumping"
        self.packet_prep = self._create_flash_packet

    def _create_flash_packet(self, addr: int) -> ReadFlashPage:
        """Create a ReadFlashPage packet for the given address."""
        return ReadFlashPage(addr, storage_type=0)

    def _unpack(self, data: bytes) -> Optional[bytes]:
        """Unpack Flash read response."""
        race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])

        if race_header.id == RaceId.RACE_STORAGE_PAGE_READ:
            packet = ReadFlashPageResponse.unpack(data)
            if packet.return_code != 0:
                logging.error(
                    "ERROR while reading at address %#x from storage type %d. Result: %d",
                    packet.page_address, packet.storage_type, packet.return_code
                )
                # Return None to indicate read failure - don't return garbage
                return None
            return packet.page_data
        # We got some unexpected packet that's not a ReadFlashPageResponse
        packet = RacePacket.unpack(data)
        logging.error(
            "ERROR got an unexpected packet with ID %#x and payload:",
            packet.header.id
        )
        hexdump(packet.payload)
        return None
