# Registry metadata repair

`normalize-store-graph.py` repairs a catalog emitter that wrote an SRI hash
inside a `nar:sha256:` token. Consumers require a bare 52-character Nix base32
digest in this position. The repair preserves the hash bytes, size, and
dependency edges; it does not accept malformed hashes or change artifacts.

Run it with an AOS-built Python on a separate, unpublished registry working
tree. The default invocation only reports changes; `--write` applies them.
After repair, sign a new catalog revision and advance its channel through the
normal publication API. Preserve previously published signed tags.

This utility validates NAR token encodings, not the complete registry schema.
Registry producers should use `NarBytes::from_hash` and the shared serializer
in `aos-registry-surface`, which already emit the canonical representation.
