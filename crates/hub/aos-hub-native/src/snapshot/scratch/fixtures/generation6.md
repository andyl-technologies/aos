# Genuine generation 6 mirror capture

These encrypted streams were captured from committed generation 6 source
`b12006112dad4612857fe5de98225b2b4fea950a` before migration 007 was declared.
The production capture and scratch verifier passed with 276 compiled tables and
266 retained tables. The retained mirror original has a fresh copy operation and
the exact full source-path index; it has no generation 7 accounting or binding
reservation columns. The fixture grants no provider authority.

The public test signer uses seed `[1; 32]`; metadata and private wrapping keys use
`[2; 32]` and `[3; 32]`. All receipt values are structural test data.

| File | SHA-256 |
| --- | --- |
| `generation6-root.json` | `31b267e7078f2536ef17b04bc60a7fffdfcebcbcda4013bbfa7b2ed0c61314d6` |
| `generation6-metadata.enc` | `d201d04fe372097fc284582bad71d7758c0d1d86a45b81959b5ba2b80c5ab37d` |
| `generation6-private.enc` | `c34e2ba04cfce192f2b85d3329227bb01d35e67bd904ab950695b95897d228d2` |
