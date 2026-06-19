# 00 — Conventions: requirement IDs, normative keywords, and how the plan threads

This file defines the machinery that makes the rest of the RFC an *implementable
specification* rather than prose: how requirements are identified, what the
normative keywords mean, and how the checkbox implementation plan threads back to
the spec so an implementor can work it one task at a time and provably reach the
target state.

## Normative keywords (RFC-2119 / RFC-8174)

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are used
with their RFC-2119 meaning, and only when in capitals. A statement without one
of these keywords is descriptive, not normative.

- **MUST / MUST NOT** — a hard requirement. A build that violates it is wrong.
  Where feasible, every MUST has a test that fails when it is violated; the test
  is named in the requirement or its checklist task.
- **SHOULD / SHOULD NOT** — a strong default. Deviations require a recorded
  rationale in [`31-decision-register.md`](31-decision-register.md).
- **MAY / OPTIONAL** — genuinely discretionary.

## Requirement IDs

Every normative statement carries a stable **requirement ID**: an area prefix, a
hyphen, and a number, e.g. `DET-3`. IDs are stable for the life of the RFC — once
assigned, an ID is never reused or renumbered; superseded requirements are marked
`(withdrawn)` in place and a new ID is added. This stability is what lets the
implementation plan and the code reference requirements durably.

A requirement is written as:

```text
- **[DET-3]** Each VM MUST produce a bit-identical instruction stream for a
  fixed (image, kernel cmdline, seed, injected-input sequence). *Gate:*
  `harness/single-vm-fingerprint`. *Spec:* §4.2.
```

i.e. the ID in bold, the normative statement, an optional **Gate** naming the
test that enforces it, and a back-pointer to the defining section.

### Area prefixes

| Prefix | Area | File |
| --- | --- | --- |
| `G` / `NG` / `INV` | Goals / Non-goals / Invariants | 01 |
| `ARCH` | Architecture-level requirements | 03 |
| `DET` | Determinism contract | 04 |
| `EXEC` | Execution model (`Configuration`/`step`/`instantiate`/`bake`) | 05 |
| `SPAT` | Spatial graph (ScenarioDef) | 06 |
| `TEMP` | Temporal graph (checkpoint DAG) | 07 |
| `SCHED` | Cross-node scheduling | 08 |
| `TIME` | Virtual time / icount | 09 |
| `QEMU` | QEMU integration (host side) | 10 |
| `PATCH` | QEMU patch series | 11 |
| `PLUG` | QEMU plugin (in-VM) | 12 |
| `SHM` | Shared-memory co-sim ABI | 13 |
| `PROTO` | IPC protocol | 14 |
| `IO` | I/O sub-nodes (disk / 9p / net devices) | 15 |
| `GHC` | Guest↔host channel | 16 |
| `FAULT` | Fault injection | 17 |
| `TRIG` | Conditions, triggers, and the event graph | 17a |
| `ASRT` | Assertions & properties | 18 |
| `OBS` | Observability / event log | 19 |
| `SESS` | Session / control plane | 20 |
| `API` | API surface | 21 |
| `ADV` | Advanced features (fork/resume/search/fuzz) | 22 |
| `CLI` | CLI | 23 |
| `HARN` | Determinism harness & testing | 24 |
| `PERF` | Performance targets | 25 |
| `PKG` | Packaging / AOS integration | 26 |
| `CRATE` | Crate structure | 27 |
| `STD` | Engineering standards | 28 |
| `PAT` | Implementation patterns & sketches | 29 |
| `RISK` | Risks & validation spikes | 30 |
| `D` | Design decisions (decision register) | 31 |
| `EX` | Worked example scenarios | 33 |
| `WL` | Workload / traffic generation | 33 |
| `TRI` | Failure triage (clustering / dedup / reporting) | 34 |
| `DCE` | Distributed & continuous exploration | 35 |
| `DBG` | Time-travel & source-level debugging | 36 |

Within a file, requirements are numbered in document order starting at 1. A file
MAY group them under sub-headings but the numbers are flat within the file.

## Task IDs and the checkbox plan

Each task has a stable, **area-scoped** ID `T-<AREA>-<n>` (e.g. `T-DET-4` = the
fourth determinism task), using the same area prefixes as requirement IDs. Stable
IDs survive reordering: the master plan ([`32-implementation-plan.md`](32-implementation-plan.md))
arranges these tasks into ordered **phases** (Phase 1 = the determinism /
harness / transport / API foundation, etc.) by *listing* their IDs, so a task can
be re-sequenced without renumbering. A task is written as a GitHub-flavored
checkbox:

```text
- [ ] **T-DET-4** Implement the single-VM execution fingerprint (periodic
  icount + register/memory hash) and the `gate:single-vm-fingerprint`
  check. — satisfies [DET-3], [HARN-2]; spec §24.3.
```

Rules:

- **[PLAN-1]** Every task MUST list the requirement IDs it satisfies and the
  spec section that defines "done."
- **[PLAN-2]** Every normative `MUST` requirement MUST be satisfied by at least
  one task. A coverage check ([`32-implementation-plan.md`](32-implementation-plan.md)
  §coverage) lists any requirement with no task — that list MUST be empty.
- **[PLAN-3]** Each topic file MUST end with an **Implementation checklist**
  section containing exactly the tasks whose primary area is that file. The topic
  checklist is the authoritative task text; the master plan is the source of truth
  for phase ordering and carries a deterministic digest of the ordered task text.
  They are kept in sync by a doc lint
  ([`28-engineering-standards.md`](28-engineering-standards.md)).
- **[PLAN-4]** Tasks are ordered so that determinism, the test harness, the
  transport ABI, and control-plane API correctness come before any feature built
  on top of them (see phase ordering in 32). A task MUST NOT depend on a
  later-phase task.

## Phase gates

Each phase ends with a **gate**: a named, automated check (a CI target) that must
be green before the next phase starts. Gates are the mechanism by which "get the
foundation completely correct first" is enforced rather than hoped for. Gates are
defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
and referenced by ID (e.g. `gate:layer0-determinism`).

## Cross-references and code links

- Cross-file references use relative links to the file and a section anchor.
- Code references, once code exists, use `crates/<crate>/src/<path>.rs:<line>`
  and reflect the tree at time of writing (per the RFCs README: an RFC is
  history; canonical docs win when they disagree).

## Voice and naming

- **[CONV-1]** This RFC and all Crucible code, comments, and docs MUST NOT refer
  to any prior internal exploration by name, nor to any third-party commercial
  product. Crucible's design is described as its own. Good findings from prior
  work are incorporated as Crucible's design; where a concrete pattern is
  borrowed, it is presented as a Crucible pattern (see
  [`29-patterns-and-sketches.md`](29-patterns-and-sketches.md)).
- The system is **Crucible**; crates are `crucible-*`; the CLI binary is
  `crucible`. "Node" means a participant in the simulation graph (a VM or an I/O
  sub-node); "host" means the machine running Crucible.

## Code sketches in this RFC

Code blocks in this RFC are **illustrative sketches**, not the implementation,
and are tagged accordingly (` ```rust `, ` ```text `, ` ```toml `). They show
intended types, signatures, and data layouts so the spec is concrete. The
authority is the prose requirement; a sketch that disagrees with a requirement is
a defect in the sketch.
