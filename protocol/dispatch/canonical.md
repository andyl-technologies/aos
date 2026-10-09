# Dispatch canonical commitments

Version 1 uses model major `1` and minor `0`. JSON `model_version` is the
canonical decimal string `"1"`; its Rust representation is an unsigned integer.
The schemas publish structural contracts. Semantic validation additionally
checks exact ranges, reduced rationals, references, uniqueness, and accounting.

Canonical bytes use RFC 8949 core deterministic CBOR. Lengths are definite;
integers use their shortest encoding. Floating point, tags, undefined values,
duplicate keys, and indefinite lengths are prohibited. Valid UTF-8 text retains
its exact bytes; Unicode normalization is not performed.

Every record becomes a CBOR map. Its unsigned integer keys are local to its type
and numbered from one in the field order below. All fields are materialized.
Optional absent values are encoded as null. Variant records retain their `kind`
text as field one; the variant fixes the remaining fields. Dictionary fields
become arrays of two-element `[text key, encoded value]` entries ordered by raw
UTF-8 key bytes. They do not become CBOR maps with application-chosen keys.

Quantities and schema versions become CBOR unsigned integers. Booleans, null,
and text use their corresponding CBOR values. A rational becomes the array
`[numerator decimal text, denominator decimal text]`, reduced with a positive
denominator. These rules apply identically to small and large quantities.

Semantically unordered collections sort their encoded elements
lexicographically by unsigned bytes. Exact duplicates are invalid. These include
domain/group/target-set memberships, scope memberships, holdings, constraints,
objective terms, eligibility selections, movement categories, metric item sets,
repair-component selections, and utilization selections. Objective tiers retain
their declared order.

## Record field orders

| Record | Fields, keys starting at one |
|---|---|
| Problem | model_version, observation_basis, items, targets, dimensions, domains, groups, target_sets, scope_families, observed, holdings, constraints, objectives |
| Dimension | unit, quantum |
| Item | domain, deferrable, demands |
| Demand | default, overrides |
| Target | capacities, fixed_load |
| Capacity finite | kind, limit |
| Capacity unbounded | kind |
| Assignment | bindings |
| Binding target | kind, target |
| Binding deferred / observed unplaced | kind |
| Observation | binding, charges |
| Holding | id, target, dimension, quantity, kind |
| HoldingKind ordinary | kind, item |
| HoldingKind additional | kind, retained_at_final |
| Constraint | id, enforcement, rule |
| Rule eligibility | kind, items, targets |
| Rule fixed_placement | kind, bindings |
| Rule capacity | kind, target_set, dimension, phase, limit |
| Rule admission | kind, group, minimum, maximum |
| Rule atomic_admission | kind, group |
| Rule co_location | kind, group, family |
| Rule spread | kind, group, family, minimum, maximum_per_member, when_admitted |
| Rule movement_budget | kind, items, costs, limit |
| AssignmentCosts | default, targets, deferred |
| MovementCosts | unit, categories, costs |
| ComponentId | constraint, component |
| ObjectiveTier | id, terms |
| ObjectiveTerm | id, direction, weight, normalizer, metric |
| UtilizationMember | id, target_set, dimension, phase, capacity |
| UtilizationReference | member, reference |
| Metric admitted_count / used_targets | kind, items |
| Metric admitted_priority | kind, priorities |
| Metric assignment_cost | kind, costs |
| Metric movement_cost | kind, items, costs |
| Metric repair_debt | kind, components |
| Metric maximum_utilization / utilization_range | kind, members |
| Metric total_absolute_deviation | kind, members |
| SolveOptions | mode, wall_time_millis, threads, seed, memory_bytes, cpu_time_millis, maximum_iterations |

Demand defaults, capacities, holding quantities, and numeric cardinality bounds
are quantities. Movement budget limits and all preference costs, weights,
normalizers, priorities, and utilization references are rationals.
`SolveOptions` integer fields are CBOR unsigned integers; an absent seed is null.

## Hash domains

```text
modelDigest = SHA256(ASCII("dispatch:model") || 0x00
                    || U32BE(modelMajor) || U32BE(modelMinor)
                    || canonicalModelBytes)
requestDigest = SHA256(ASCII("dispatch:request") || 0x00
                      || canonicalRequestBytes)
```

The model includes the entire observation basis, observed assignment, and
concurrent holdings. It does not include execution policy, hint, labels, or
trace bookkeeping. The model schema provides no semantic extension through
those excluded fields.

A solve request is a six-field map: key one is the model digest as a 32-byte
CBOR byte string; key two is the selected backend name as text; key three is
`SolveOptions`; key four is the optional canonical Assignment hint or null;
key five is the request-schema version array `[1, 0]`; key six is text `solve`.
The remaining wall-time field propagated between execution stages is not part
of this commitment. The options contain the original requested budget. Results
record reduced effective options separately.

## Golden vectors

`vectors.json` contains manually specified CBOR and Protobuf octets plus their
domain-separated SHA-256 identities. The empty model is structurally valid,
with no items, dimensions, targets, or obligations. Its encoded map has thirteen
fields. The Hello vector demonstrates the four-byte big-endian length prefix.

Regeneration must preserve the published semantics: independently encode the
listed records, compare the exact bytes, then hash the domain separator and
version prefix. Reordered set membership and dictionary entries must preserve
identity; reordered objective tiers must not. A release must test the vectors
through both Rust and the native worker schema implementation.
