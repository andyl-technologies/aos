"""Bind fresh Native measurement inputs to immutable phase templates.

The template contains current admitted originals, not a signed plan or lease.
Each actual Native original receives its own at-most25s selector immediately
before dispatch, always within the earlier enclosing window. No failed original
is rewritten, renewed or reused.
"""

import hashlib
import json
from pathlib import Path
import time

from bridge import read_private, write_private


class FreshNativeCallbacks:
    def __init__(self, native, root, cutoff):
        self.native = native
        self.root = Path(root)
        self.cutoff = cutoff
        self.used = set()
        self.references = []

    def selection(self, reference):
        raw = read_private(reference["file"], 65536)
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != reference["bytes"] or digest != reference["sha256"] or digest in self.used:
            raise ValueError("Native phase template changed or was reused")
        template = json.loads(raw)
        if (set(template) != {"version", "helperInputFile", "helperInputSha256", "outputFile", "phase"}
                or type(template["version"]) is not int or template["version"] != 1
                or Path(template["outputFile"]).parent != self.root):
            raise ValueError("Native phase template output or schema differs")
        remaining = self.cutoff - time.monotonic()
        # Leave the final selector second and cleanup inside its original
        # parent. Core's actual conservative clock is authoritative on dispatch.
        span = min(25, int(remaining))
        if span <= 3:
            raise TimeoutError("Native phase has no original dispatch budget")
        selected = {**template, "cutoffUnixSeconds": int(time.time()) + span}
        self.used.add(digest)
        actual = write_private(self.root / ("selected-" + digest + ".json"), selected, 65536)
        self.references.append({"template": reference, "actualSelection": actual})
        return actual

    async def inspect_pack(self, reference):
        return await self.native.inspect_pack(self.selection(reference))

    async def metadata(self, reference):
        if set(reference) != {"selection", "candidateBuffersHeaderFile"}:
            raise ValueError("Native metadata callback input schema differs")
        return await self.native.metadata({**reference, "selection": self.selection(reference["selection"])})

