# Generation 5 capture fixture

These signed, encrypted bytes were captured and verified by the production
generation 5 code at committed source
`d23736884279e099f2760fd7a771d393fe2bde51`, before migration 006 was declared.
The existing Native scratch fixture populated the real generation 5 SQLite
schema with example users, a registry and a committed mirror record, then ran
the production capture and retained-constraint verification paths.

The mirror original has no copy operation identifier or indexed path columns.
Its private source and progress bytes exercise genuine historical compatibility;
no schema headers, migration commitments or private originals were rewritten.
The example provider receipts are structural test data, not authenticated
provider evidence or restored mutation authority.

The signing seed and wrapping keys are public test values `[1; 32]`, `[2; 32]`
and `[3; 32]`. Generation 6 verification must preserve this archive through its
matching generation 5 DDL and reject incomplete or changed private streams.

| File | SHA-256 |
| --- | --- |
| `generation5-root.json` | `4217dfaf32243c00eacb5412dde6a927822ab9938a0d0dd26416e0b0d61863b0` |
| `generation5-metadata.enc` | `6c8540d343f7dab9adb530fff6c725d21cecb932a67b432672af22abd65c8984` |
| `generation5-private.enc` | `9cf78eac6f5d91e126162fe372efabd64a24d983a7e1817b19d305a48587738e` |
