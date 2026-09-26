# 00 — Conventions

This file defines how the specification is written and read: which words are
normative, how requirements are identified and tested, how files reference
each other, and what a conforming document in this set looks like. It is the
first file to read and the file every other file assumes.

## Normative keywords

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** carry
their RFC 2119 and RFC 8174 meaning when, and only when, written in capitals.
A statement without one of these words is descriptive and carries no
conformance weight.

- **MUST / MUST NOT** — a hard requirement. Where feasible the requirement
  names a gate that fails when it is violated.
- **SHOULD / SHOULD NOT** — a strong default. An implementation that deviates
  records why, and this specification records its own deviations in
  [`39-decision-register.md`](39-decision-register.md).
- **MAY / OPTIONAL** — discretionary.

## Requirement IDs

Every normative statement carries a stable identifier: an area prefix, a
hyphen, and a number, for example `TREE-4`. Numbers are flat within a file
and assigned in document order starting at 1. An ID is never reused or
renumbered. A withdrawn requirement stays in place marked `(withdrawn)` and any
replacement receives a new ID.

A requirement is written as:

```text
- **[TREE-4]** A node MUST be encoded as the canonical CBOR map defined in
  `reference/terrane-v1.cddl`. *Gate:* `gate:canonical-cbor`. *See:* §3.2.
```

The ID in bold, the statement, an optional **Gate** naming the automated check
that enforces it, and an optional **See** pointing at the section that
explains it.

### Area prefixes

| Prefix | Area | File |
| --- | --- | --- |
| `CONV` | These conventions | 00 |
| `G` / `NG` / `INV` | Goals / non-goals / invariants | 01 |
| `ARCH` | Architecture | 03 |
| `OBJ` | Content model and identity | 04 |
| `CDC` | Chunking and compression | 05 |
| `TREE` | Tree structure and encoding | 06 |
| `ALG` | Tree algebra | 07 |
| `PROP` | Properties | 08 |
| `REF` | Refs and commits | 09 |
| `DRV` | Derived data | 10 |
| `STORE` | Store interface and composition | 11 |
| `PACK` | Pack format and indexes | 12 |
| `BKT` | Bucket layout | 13 |
| `HOST` | Host tier | 14 |
| `RED` | Redundancy | 15 |
| `BLK` | Block-device backend | 16 |
| `GC` | Garbage collection | 17 |
| `PROTO` | Wire protocol | 18 |
| `TOPO` | Tiering and topology | 19 |
| `CONS` | Consistency | 20 |
| `BW` | Bandwidth | 21 |
| `AUTH` | Authentication and authorization | 22 |
| `PROV` | Provenance and trust | 23 |
| `DOM` | Disclosure domains | 24 |
| `THREAT` | Threat model | 25 |
| `SURF` | Surfaces | 26 |
| `FUSE` | FUSE surface | 27 |
| `EROFS` / `VBLK` | EROFS surface / block surface | 28 |
| `VM` | Virtual-machine surfaces | 29 |
| `NIX` / `REAPI` / `GHA` / `GIT` / `OCI` / `WEB` | Protocol surfaces | 30 |
| `RULE` | Routing rulesets | 31 |
| `JOB` | Tree jobs | 32 |
| `MIG` | Migrations | 33 |
| `OBS` | Observability | 34 |
| `PERF` | Performance targets | 35 |
| `TEST` | Testing and conformance | 36 |
| `CRATE` | Crate structure | 37 |
| `EDGE` | WebAssembly and edge | 38 |
| `D` | Decisions | 39 |
| `RISK` | Risks and open questions | 40 |

## Gates

A gate is a named automated check, written `gate:<name>`. Gates are defined
in [`36-testing-and-conformance.md`](36-testing-and-conformance.md) and
referenced by name from requirements. A conformance level is met when every
gate named by the level's files passes.

- **[CONV-1]** Every `MUST` requirement in a file that a conformance level
  names SHOULD name a gate. A `MUST` without a gate is listed in
  [`36-testing-and-conformance.md`](36-testing-and-conformance.md) §ungated
  with a reason.

## Normative and informative material

- Files `01` through `38` are normative except where a section is headed
  "Informative" or where prose carries no normative keyword.
- [`39-decision-register.md`](39-decision-register.md) and
  [`40-risks-and-open-questions.md`](40-risks-and-open-questions.md) record
  rationale and are informative.
- Under `reference/`, the CDDL, the protocol schema, the golden vectors, and
  the registries are normative when a requirement cites them. Prior art and
  comparisons are informative.
- Where prose and the CDDL or a golden vector disagree, the CDDL or vector
  wins and the prose is corrected.

## Task plans

This specification does not carry implementation checklists. An adopting
project keeps its own plan outside this directory and threads tasks back to
requirement IDs. This keeps the specification stable while adoption moves.

## Cross-references

- References between files use relative links with a section anchor where one
  exists, for example `[`06-tree-format.md`](06-tree-format.md#node-encoding)`.
- References to reference documents use `reference/<file>`.
- A file MUST NOT link outside this directory. Adopting projects link inward.

## Identity, naming, and voice

- **[CONV-2]** The specification describes Terrane as its own system. It
  does not name a host operating system, product, or prior internal system in
  files `01` through `38` or in the normative reference documents. Public
  protocols, public projects, and published research MAY be cited by name.
  Informative reference documents MAY compare against named systems.
- **[CONV-3]** Every identity domain, media type, property name, surface
  name, bucket key prefix, and gate name is registered in a reference
  document before it is used. Unregistered names are conformance errors.
- Byte-level formats are given as CDDL and, where the format is not CBOR, as
  a field table with offsets, widths, and byte order. Every fenced block is
  tagged with a language.
- Prose uses the vocabulary of [`02-glossary.md`](02-glossary.md). Where a
  term is introduced for the first time in a file, it links to the glossary.

## Document shape

Each topic file has the same shape so a reader can navigate by habit:

1. A title `# NN — Title` and one paragraph stating what the file owns.
2. A short **Model** or **Overview** section explaining the design in prose
   before any requirement.
3. Sections of requirements grouped by concern, each requirement on its own
   bullet with its ID.
4. An **Interactions** section naming the other files this one constrains or
   depends on.
5. Optional **Informative** sections: examples, rationale summaries, and
   pointers into [`39-decision-register.md`](39-decision-register.md).

Lines wrap at 80 columns. Tables are used for registries, budgets, and
comparisons; prose is used for everything that needs a verb.
