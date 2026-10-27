# SPDX-License-Identifier: MIT
"""Owns one bounded in-memory 9p2000.L fixture tree, without host filesystem I/O.

The tree contains only its root and a regular file named probe. It implements
operations needed by the actual Linux read/write/flush fixture and returns
protocol errors for other names or operations. This is a functional test
server, not a general filesystem backend or an exact capture authority.
"""

import struct


class RequestReader:
    """Consumes a complete bounded request body without accepting trailing data."""

    def __init__(self, payload):
        self.payload = payload
        self.offset = 7

    def values(self, layout):
        size = struct.calcsize("<" + layout)
        if size > len(self.payload) - self.offset:
            raise RuntimeError("truncated finite 9p request")
        values = struct.unpack_from("<" + layout, self.payload, self.offset)
        self.offset += size
        return values

    def string(self):
        length, = self.values("H")
        return self.bytes(length)

    def bytes(self, length):
        if length > len(self.payload) - self.offset:
            raise RuntimeError("truncated finite 9p byte extent")
        value = self.payload[self.offset:self.offset + length]
        self.offset += length
        return value

    def finish(self):
        if self.offset != len(self.payload):
            raise RuntimeError("finite 9p request contains trailing fields")


class FiniteNinepFixture:
    """Serves a fixed file with an explicitly negotiated 4096-byte message cap."""

    def __init__(self):
        self.negotiated_message_bytes = None
        self.fids = {}
        self.created = False
        self.data = bytearray()
        self.operations = {}
        self.flushed_bytes = None

    def qid(self, name):
        return struct.pack("<BIQ", 0x80 if name == b"/" else 0, 1,
                           1 if name == b"/" else 2)

    def reply(self, request):
        if not 7 <= len(request) <= 4096:
            raise RuntimeError("9p request exceeds the finite message extent")
        length, opcode, tag = struct.unpack_from("<IBH", request)
        if length != len(request) or opcode & 1:
            raise RuntimeError("invalid finite 9p request header")
        if opcode != 100 and (self.negotiated_message_bytes is None
                              or len(request) > self.negotiated_message_bytes):
            raise RuntimeError("9p request lacks its negotiated finite message custody")
        reader = RequestReader(request)
        self.operations[opcode] = self.operations.get(opcode, 0) + 1
        if sum(self.operations.values()) > 1024:
            raise RuntimeError("finite 9p operation budget exhausted")

        try:
            payload = self.dispatch(opcode, reader)
            response_opcode = opcode + 1
        except OSError as error:
            # 9p2000.L uses Rlerror with a positive Linux errno.
            payload = struct.pack("<I", error.errno)
            response_opcode = 7
        if (self.negotiated_message_bytes is None
                or len(payload) + 7 > self.negotiated_message_bytes):
            raise RuntimeError("finite 9p reply exceeds message capacity")
        return struct.pack("<IBH", len(payload) + 7, response_opcode, tag) + payload

    def name(self, fid):
        if fid not in self.fids:
            raise OSError(9, "unknown finite fixture fid")
        return self.fids[fid]

    def bind(self, fid, name):
        if fid in self.fids or len(self.fids) >= 64 or fid == 0xffffffff:
            raise RuntimeError("finite 9p fid custody collision or exhaustion")
        self.fids[fid] = name

    def dispatch(self, opcode, reader):
        if opcode == 100:  # Tversion
            size, = reader.values("I")
            version = reader.string()
            reader.finish()
            if version != b"9P2000.L" or size < 256:
                raise RuntimeError("unsupported finite fixture protocol negotiation")
            self.negotiated_message_bytes = min(size, 4096)
            self.fids.clear()
            return struct.pack("<IH", self.negotiated_message_bytes, 8) + b"9P2000.L"

        if opcode == 104:  # Tattach
            fid, auth = reader.values("II")
            reader.string()  # Caller identity cannot select another host tree.
            tree = reader.string()
            uid, = reader.values("I")
            reader.finish()
            if auth != 0xffffffff or tree:
                raise OSError(22, "finite fixture has no auth or alternate tree")
            self.bind(fid, b"/")
            return self.qid(b"/")

        if opcode == 110:  # Twalk
            fid, newfid, count = reader.values("IIH")
            if count > 16:
                raise RuntimeError("finite 9p walk exceeds path component budget")
            names = [reader.string() for _ in range(count)]
            reader.finish()
            name = self.name(fid)
            qids = []
            for component in names:
                if name == b"/" and component == b"probe" and self.created:
                    name = b"probe"
                elif component in (b".", b".."):
                    name = b"/" if component == b".." else name
                else:
                    raise OSError(2, "finite fixture entry does not exist")
                qids.append(self.qid(name))
            if newfid == fid:
                self.fids[fid] = name
            else:
                self.bind(newfid, name)
            return struct.pack("<H", count) + b"".join(qids)

        if opcode == 24:  # Tgetattr, Linux's actual 9p2000.L attribute layout.
            fid, mask = reader.values("IQ")
            reader.finish()
            name = self.name(fid)
            mode = 0o40755 if name == b"/" else 0o100600
            size = 0 if name == b"/" else len(self.data)
            values = [2 if name == b"/" else 1, 0, size, 4096, (size + 511) // 512]
            values += [0] * 10
            return (struct.pack("<Q", mask & 0x7ff) + self.qid(name) +
                    struct.pack("<III", mode, 0, 0) + struct.pack("<15Q", *values))

        if opcode == 14:  # Tlcreate changes this directory fid to the new file.
            fid, = reader.values("I")
            name = reader.string()
            flags, mode, gid = reader.values("III")
            reader.finish()
            if self.name(fid) != b"/" or name != b"probe":
                raise OSError(22, "finite fixture creation is limited to probe")
            self.created = True
            self.fids[fid] = b"probe"
            if flags & 0x200:  # O_TRUNC
                self.data.clear()
            return self.qid(b"probe") + struct.pack("<I", self.negotiated_message_bytes - 24)

        if opcode == 12:  # Tlopen
            fid, flags = reader.values("II")
            reader.finish()
            name = self.name(fid)
            if name == b"probe" and flags & 0x200:
                self.data.clear()
            return self.qid(name) + struct.pack("<I", self.negotiated_message_bytes - 24)

        if opcode in (116, 118):  # Tread/Twrite
            fid, offset, count = reader.values("IQI")
            if count > self.negotiated_message_bytes - 24 or offset > 65536 or count > 65536 - offset:
                raise RuntimeError("finite fixture file byte budget exceeded")
            data = reader.bytes(count) if opcode == 118 else b""
            reader.finish()
            if self.name(fid) != b"probe":
                raise OSError(21, "finite fixture root is a directory")
            if opcode == 116:
                data = bytes(self.data[offset:offset + count])
                return struct.pack("<I", len(data)) + data
            if len(self.data) < offset + count:
                self.data.extend(bytes(offset + count - len(self.data)))
            self.data[offset:offset + count] = data
            return struct.pack("<I", count)

        if opcode == 50:  # Tfsync
            fid, datasync = reader.values("II")
            reader.finish()
            if self.name(fid) != b"probe" or datasync not in (0, 1):
                raise OSError(22, "invalid finite fixture flush")
            self.flushed_bytes = bytes(self.data)
            return b""

        if opcode == 120:  # Tclunk
            fid, = reader.values("I")
            reader.finish()
            self.name(fid)
            del self.fids[fid]
            return b""

        if opcode == 8:  # Tstatfs
            fid, = reader.values("I")
            reader.finish()
            self.name(fid)
            return struct.pack("<II6QI", 0x01021997, 4096, 16, 15, 15, 2, 0, 1, 255)

        if opcode == 30:  # Txattrwalk: this finite tree has no xattrs or ACLs.
            fid, newfid = reader.values("II")
            reader.string()
            reader.finish()
            self.name(fid)
            raise OSError(95, "finite fixture does not support extended attributes")

        raise RuntimeError(f"actual Linux requested unimplemented finite 9p opcode {opcode}")
