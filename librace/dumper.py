import asyncio
import io
import logging

from tqdm import tqdm
from hexdump2 import hexdump

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
    def __init__(self, progress: bool):
        self.stop_event = asyncio.Event()
        self.outbuf = b""
        self.progress = progress

    async def dump(self, addr: str = None, size: int = None, fd: io.IOBase = None):
        await self.r.setup(self.recv)

        if addr is not None and size is not None:
            self.start = addr
            self.size = size

        self.fd = fd

        # Calculate total units for progress bar
        TOTAL_UNITS = self.size // self.unit_size

        if self.progress:
            with tqdm(
                total=TOTAL_UNITS, desc=f"{self.verb} {self.desc}", unit=self.unit
            ) as pbar:
                address = self.start
                while address < self.start + self.size:
                    race_packet = self.packet_prep(address)
                    await self.send(race_packet)

                    # Wait for response before proceeding to the next page
                    await self.await_response()

                    # Update progress bar by one UNIT
                    pbar.update(1)
                    address += self.unit_size
            logging.info(f"{self.desc} dump completed successfully.")
        else:
            address = self.start
            while address < self.start + self.size:
                race_packet = self.packet_prep(address)
                logging.debug(f"Sending {hex(address)}/{hex(self.start + self.size)}")
                logging.debug(f"\n{hexdump(race_packet.pack(), 'return')}")
                await self.send(race_packet)

                # Wait for response before proceeding to the next page
                await self.await_response()

                address += self.unit_size

        o = self.outbuf
        self.outbuf = b""
        return o

    async def send(self, race_packet: RacePacket):
        await self.r.send(race_packet)

    def recv(self, data: bytes):
        if not self.progress:
            logging.debug("Received response:")
            logging.debug(f"\n{hexdump(data, 'return')}")
        unpacked = self._unpack(data)
        if unpacked:
            if type(unpacked) is bytes:
                # Write to the open file handle
                if self.fd:
                    self.fd.write(unpacked)
                    self.fd.flush()
                self.outbuf += unpacked

            # Signal main loop to proceed
            self.stop_event.set()

    async def await_response(self):
        await self.stop_event.wait()
        self.stop_event.clear()


class RACERAMDumper(RACEDumper):
    def __init__(self, r: RACE, start: int, size: int, progress: bool = True):
        super().__init__(progress)
        self.r = r
        self.start = start
        self.size = size
        self.unit_size = 0x4
        self.unit = "word"
        self.desc = "RAM"
        self.verb = "Dumping"
        self.packet_prep = lambda addr: ReadAddress(addr)

    def _unpack(self, data: bytes):
        race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])

        if race_header.id == RaceId.RACE_READ_ADDRESS:
            packet = ReadAddressResponse.unpack(data)
            if packet.return_code != 0:
                logging.error(
                    f"ERROR while reading at address {packet.page_address:#2x} from storage type {packet.storage_type}. Result: {packet.return_code}"
                )
            return packet.page_data
        else:
            packet = RacePacket.unpack(data)
            logging.error(
                f"ERROR got an unexpected packet with ID {packet.header.id:#2x} and payload:"
            )
            hexdump(packet.payload)


class RACEFlashDumper(RACEDumper):
    def __init__(self, r: RACE, start: int, size: int, progress: bool = True):
        super().__init__(progress)
        self.r = r
        self.start = start
        self.size = size
        self.unit_size = 0x100
        self.unit = "page"
        self.desc = "Flash"
        self.verb = "Dumping"
        self.packet_prep = lambda addr: ReadFlashPage(addr, storage_type=0)

    def _unpack(self, data: bytes):
        race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])

        if race_header.id == RaceId.RACE_STORAGE_PAGE_READ:
            packet = ReadFlashPageResponse.unpack(data)
            if packet.return_code != 0:
                logging.error(
                    f"ERROR while reading at address {packet.page_address:#2x} from storage type {packet.storage_type}. Result: {packet.return_code}"
                )
            return packet.page_data
        else:  # We got some unexpected packet thats not a ReadFlashPageResponse
            packet = RacePacket.unpack(data)
            logging.error(
                f"ERROR got an unexpected packet with ID {packet.header.id:#2x} and payload:"
            )
            hexdump(packet.payload)
