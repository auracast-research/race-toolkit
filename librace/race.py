import asyncio
from typing import Callable

from librace.constants import RaceType
from librace.transport import Transport

from librace.packets import RaceHeader, RacePacket


class RACE:
    """This class implements the RACE protocol via a given Transport. It receives full packets and parses the header. Parsing the packet data is the responsibility of the user."""

    def __init__(self, transport: Transport, send_delay: float):
        self.transport = transport
        self.full_payload = b""
        self.sync_payload = b""
        self.expected_length = None
        self.recv_cb = None
        self.stop_event = asyncio.Event()
        self.send_delay = send_delay

    async def send(self, race_packet: RacePacket):
        if self.send_delay > 0:
            await asyncio.sleep(self.send_delay)
        await self.transport.send(race_packet.pack())

    async def send_sync(self, race_packet: RacePacket):
        if self.send_delay > 0:
            await asyncio.sleep(self.send_delay)
        await self.transport.send(race_packet.pack())
        await self.stop_event.wait()
        self.stop_event.clear()
        r = self.sync_payload
        return r

    async def setup(self, recv_cb: Callable = None):
        self.recv_cb = recv_cb
        await self.transport.setup(self._recv)

    async def close(self):
        await self.transport.close()

    def reset(self):
        self.recv_cb = None
        self.expected_length = None
        self.full_payload = b""
        self.sync_payload = b""
        self.stop_event = asyncio.Event()

    def _recv(self, data: bytes):
        if self.expected_length is None:
            self.full_payload += data

            # we already received some data, but until now not enough to fully parse the RACE header, maybe now?
            if len(self.full_payload) >= RaceHeader.SIZE:
                data = self.full_payload

            if len(data) >= RaceHeader.SIZE:
                # First fragment, parse the RaceHeader
                race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])
                self.expected_length = race_header.length
                self.full_payload = data
            else:
                return
        else:
            # Continuation, we expact raw payload only. No RaceHeader.
            self.full_payload += data

        # Have we gotten all the continuation data?
        if len(self.full_payload) - 4 >= self.expected_length:
            race_header = RaceHeader.unpack(self.full_payload[: RaceHeader.SIZE])

            if self.recv_cb:
                self.recv_cb(self.full_payload)

            self.sync_payload = self.full_payload
            # only stop blocking once we got the actual reponse, not the response indication
            if race_header.type == RaceType.RESPONSE:
                self.stop_event.set()

            self.full_payload = b""
            self.expected_length = None
