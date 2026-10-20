# Generation 4 capture fixture

The three `generation4-*` files are an actual signed, encrypted capture from
committed source `a19869736aab0e047dce1cb33c0eaa661a921491`, whose production
migration list contained exactly four scripts. The existing core archive test
fixture created the SQLite source and ran the production capture and verification
code with deterministic test keys and randomness. Schema headers and migration
commitments were not rewritten to make this historical fixture.

The fixture contains example users, private example password strings and
transient authentication rows. Its signing seed and wrapping keys are the
existing public test values `[1; 32]`, `[2; 32]` and `[3; 32]`.

The source capture and verification gate passed before migration 005 was
declared. Generation 5 scratch verification must use the genuine generation 4
DDL, preserve private originals, check retained constraints, and reject a
truncated encrypted stream.

| File | SHA-256 |
| --- | --- |
| `generation4-root.json` | `6096290ba2f09dcf899a8ec4529393f562b27b843c88868bd63f74c44d6c6da5` |
| `generation4-metadata.enc` | `e6ef25c1b6a2f8fb17d4759187abd9035d074025564f79b3cda2a1511c72b598` |
| `generation4-private.enc` | `74b016584e6124ddeb1e629d0d216ce9b84ea606bf6c27619bd9c983e95dff8c` |
