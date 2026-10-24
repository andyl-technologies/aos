# Compute source compatibility fixtures

These fixed vectors were captured from revision
`0ab383efbdc72a8435ddd7342adec5cfc8a4132c` before the RFC-0025 source-role
renames. The generator ran against an archive of that revision's Cargo
workspace, using the fixture setup in `compute_source_compatibility.rs` with
the original `WorldNode`, `NodeTemplate`, and `DeviceSchedulingSubNode` names.

The vectors cover a heterogeneous world with x86-64 and AArch64 compute nodes,
a block node, a logical link, image references, and nondefault compute settings.
They preserve canonical material, TOML, compact binary, scheduler identity JSON,
an I/O checkpoint with pending reads submitted in reverse arrival order, and
the resulting delivery trace. Hex files represent exact encoded bytes.

The tests compare the renamed API with these parent-revision vectors and decode
the old encodings. They also restore the pending I/O checkpoint after its
completions have been consumed, checking exact delivery and absence of duplicate
completions. Update these vectors only for an intentional format or semantic
migration, not to accommodate another source rename.
