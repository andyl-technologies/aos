"""Fixed local IPC for the selected owned TLS source; no provider control API."""

import asyncio
import json
from pathlib import Path
import os
import time


class OwnedPackHold:
    def __init__(self, private_root, cutoff):
        root = Path(private_root)
        actual = root.lstat()
        if not root.is_absolute() or not root.is_dir() or root.is_symlink() or actual.st_uid != os.getuid() or actual.st_mode & 0o077:
            raise ValueError("selected local holder root differs")
        self.socket = str(root / "source.sock")
        self.cutoff = cutoff
        self.released = False
        self.metadata_released = False
        self.receipts = []

    async def _control(self, action):
        remaining = self.cutoff - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("original source control cutoff reached")
        async def exchange():
            reader, writer = await asyncio.open_unix_connection(self.socket)
            try:
                body = json.dumps({"action": action}, separators=(",", ":")).encode()
                writer.write(b"POST /control HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: "
                    + str(len(body)).encode() + b"\r\n\r\n" + body)
                await writer.drain()
                header = await reader.readuntil(b"\r\n\r\n")
                if len(header) > 8192 or not header.startswith(b"HTTP/1.1 200 "):
                    raise ValueError("actual holder control response differs")
                lengths = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")]
                if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) > 32768:
                    raise ValueError("actual holder control byte bound differs")
                value = json.loads(await reader.readexactly(int(lengths[0])))
                self.receipts.append(value)
                if len(self.receipts) > 512:
                    raise ValueError("holder control corpus overflow")
                return value
            finally:
                writer.close()
        task = asyncio.create_task(exchange())
        done, _ = await asyncio.wait({task}, timeout=remaining)
        if not done:
            task.cancel()
            raise TimeoutError("original holder response cutoff reached")
        value = task.result()
        if time.monotonic() >= self.cutoff:
            raise TimeoutError("holder response arrived after original cutoff")
        return value

    async def _wait(self, roles):
        while True:
            row = await self._control("state")
            if set(roles).issubset(row["held"]):
                return row
            remaining = self.cutoff - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("owned held originals absent before cutoff")
            await asyncio.sleep(min(0.25, remaining))

    async def wait_received(self):
        return await self._wait({"pack"})

    async def wait_metadata_received(self):
        return await self._wait({"pack", "metadata0", "metadata1"})

    async def release_metadata_once(self):
        if self.metadata_released:
            raise ValueError("metadata original release reused")
        self.metadata_released = True
        return await self._control("release_metadata")

    async def release_once(self):
        if self.released:
            raise ValueError("pack original release reused")
        self.released = True
        return await self._control("release_pack")

    async def cancel(self):
        # Actual owner retirement closes original sockets; it grants no drain.
        return await self._control("retire")
