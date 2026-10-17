# Extension registration and installed selection

This plan addresses CN-EXT-1 through CN-EXT-9 in RFC-0025 chapter 09. It
separates portable declaration data, configured namespace trust, semantic
validation, negotiation, immutable admission, and native qualification.

## Current implementation

The portable value layer carries closed core objects and bounded `Extensions`
maps. Canonical hashing retains identity-bearing extension data. Provider
manifests advertise extension feature identifiers. `NegotiationPolicy` maps
explicit envelope keys to selected feature identifiers, and
`ConnectionAuthority` retains the admitted envelope-key set. The connection's
mandatory `BodySchemaVerifier` remains responsible for method and nested
extension semantics.

Whole-graph admission refuses nonempty identity-bearing extension maps in
node bindings, descriptors, capabilities, guarantees, ports, lanes, schemas,
owners, and connections. That refusal prevents a hashed vendor object from
acquiring support. It also means general vendor extension admission is not
implemented.

The relevant source boundaries are:

| Boundary | Existing source | Missing integration |
| --- | --- | --- |
| Portable declaration | `crucible-node-contract/src/values.rs`, `schema/` | Complete extension registration records and bounded exact selections |
| Handshake | `crucible-node-provider/src/handshake/negotiation.rs` | Explicit selected version/schema identity and immutable selection across reconnect |
| Method dispatch | `crucible-node-provider/src/connection.rs` | Installed per-location semantic validators and finite extension credits |
| Graph admission | `crucible/src/node_admission/{nodes,ports,graph}.rs` | Selected registration closure bound to execution identity, retaining unknown refusal |
| Actual provider | `crucible-node-provider/src/reference_service/` | A distinct installed profile exercising registered selection without altering legacy profiles |
| Evidence | `crucible-node-provider/src/conformance/` | Required/optional selection, namespace, schema, scope, bounds, and downgrade probes against an actual endpoint |

`HelloResult` currently returns selected feature identifiers. A feature suffix
such as `/1` alone is not an explicit selection of a complete declaration,
semantic version, and schema digest. A trusted verifier can enforce a private
installed interpretation, but that does not provide the portable registration
and selection interface required by chapter 09.

The current handshake checks every selected feature against the current
offered, supported, and required sets. It does not retain and compare the
complete original selected feature set during resume. A previously selected
optional feature can therefore disappear at that layer. Core installed
adapters can separately refuse the resulting contract; the common handshake
still needs its own immutable selection check.

## Portable data records

A new independent value module should define the records below. They remain
plain bounded data and import no emulator, native ABI, callback, or authority
type. No declaration constructor can authenticate namespace ownership or
qualify a provider.

`ExtensionDeclaration` contains exactly the chapter 09 registration inventory:

| Field | Validation and use |
| --- | --- |
| `identifier` | Bounded canonical semantic identifier; separately checked against the configured namespace and reserved core inventory |
| `owner` | Configured namespace authority identity and immutable publication origin |
| `semantic_version` | Exact bounded published version; no implicit compatible-version range |
| `schema_digest` | Exact canonical schema identity, matched against the complete referenced schema bytes |
| `specification` | Immutable content reference sufficient for independent implementation |
| `dependencies` | Sorted unique exact core or extension contracts; complete bounded closure required |
| `required_features` | Sorted feature identities required for selection and use |
| `applicability` | Explicit operation direction, object location, or port/lane scopes |
| `timing_effects` | Immutable semantic definition of boundaries, resolution, and causal obligations |
| `state_effects` | Immutable ownership, capture, compatibility, and future-state definition |
| `error_behavior` | Immutable refusal, uncertainty, retry, cancellation, and disposition definition |
| `limits` | Explicit finite message, object, allocation, queue, and operation bounds |
| `conformance` | Exact positive/negative case definitions and applicable evidence classes |

Referenced definitions are complete content objects, not prose labels accepted
as executable support. A schema digest must identify actual schema bytes under
the declared canonical schema format. Declaration, specification, schema,
dependency, timing, state, error, and conformance objects all contribute to the
selected registration identity.

`ExtensionSelection` identifies the selected declaration reference,
identifier, exact semantic version, and schema digest. These values are
explicitly compared with the installed registry. Selecting the correct feature
identifier with another schema or specification is refused.

Declarations and selections use the existing strict JSON parser, required
nullable-field rules, canonical encoding, array/depth bounds, checked wide
integers, and domain-separated content identities. Smaller installed registry
limits bound aggregate declarations, dependency references, and definition
bytes before allocation. The public format does not accept native pointers or
handler identities.

## Installed registry and trust

The host registry is built from configured trusted installation records before
provider selection. Namespace validation checks the authenticated publication
origin and configured owner-controlled identifier scope. Vendor ownership
cannot redefine a reserved core role, port, feature, error, operation, or
profile. An `owner` string in a provider declaration never authenticates itself.

Each installed entry retains:

1. The original complete declaration and verified definition bytes.
2. Its configured namespace authorization and reserved-identifier policy.
3. The actual installed semantic validator for each applicable location.
4. The exact implementation/configuration qualification accepted for its use.
5. Finite receiving and retained-state credits.

Registration and qualification remain distinct. A structurally valid schema
does not establish timing accuracy, complete capture, native ownership,
physical suspension, or executable support. Existing host source and native
receipt verifiers remain mandatory.

An installed validator checks the selected declaration, exact application
scope, body/schema, resource bounds, timing/state obligations, and error
disposition before any corresponding native effect. A handler for an envelope
extension does not authorize the same identifier in a port, capture record,
error code, or operation result.

The default registry is empty except for explicit installed core contracts.
Unknown required definitions and missing handlers refuse. General extension
maps must not become permissive merely because the registry type exists.

## Explicit negotiation

A separately registered negotiation feature can carry bounded offered and
selected `ExtensionSelection` records inside the permitted hello extension
object. Its identifier and schema are part of its published definition; the
candidate name `cnp.extension-registry/1` is provisional until registration and
the implementation review are complete. It is not currently advertised.

The exchange verifies all of the following before registration or realization:

1. Every selected declaration was offered, installed, and mutually supported.
2. Every required selection is returned explicitly with matching version and
   schema digest.
3. Namespace authorization, definition bytes, dependency closure, and actual
   semantic handlers are available.
4. Required features and definition/application scopes agree.
5. Selected finite limits fit both endpoints and their retained obligations.
6. The provider identity matches independently measured installation facts.

Unsupported optional offers remain unselected. They cannot reach semantic
dispatch, enter an admitted execution binding, change guest interaction,
permission, modeled state identity, or advertised guarantees. Unselected
extension payloads appearing in later method or descriptor objects still
refuse; offering a feature is not permission to use its payload.

Immutable original wire requests remain under the existing retry journal.
Execution compatibility records bind selected semantic contracts rather than
inferring acceptance from opaque bytes or from an unrelated successful call.

## Immutable world and reconnect selection

The first authenticated selection produces an immutable selection snapshot:
provider/implementation identity, exact selected feature set, exact selected
extension records, schema and specification identities, applicable scopes,
and semantic/resource contracts. The actual registration lease retains this
snapshot; it does not turn that data into native effect authority.

Resume compares the complete original semantic snapshot before accepting a new
stream. A missing optional feature that was selected and used is a downgrade,
not a harmless optional offer. Changed definitions, scope, version, schema,
requirements, timing, state, or qualified capability require a newly admitted
world or an explicitly registered conversion. Existing operations remain under
their original IDs, outcomes, and supervision on refusal.

Operational limits can refuse additional work without rewriting an admitted
contract or discarding existing obligations. A smaller transport allowance
cannot release original blob, request, operation, or native resource custody.
The existing single-connection fencing, surviving incarnation checks,
independent peer measurement, and retained native-journal verification remain
necessary.

Selected behavior-affecting declarations enter durable compatibility through
explicit registered identity-bearing binding fields. They do not belong only
in the live `NodeBinding` wrapper or `LiveAuthority`, whose operational fields
are excluded from durable compatibility identity. The entire graph checks the
same selected closure before readiness and activation.

## Compatibility and legacy behavior

The control version, extension semantic contract, guest device ABI, port
contract, shared-memory ABI, capture format, execution binding, observation
schema, and scenario format remain separate compatibility domains. None can
be inferred from a successful parser, boot, feature name, or another domain's
version number.

Existing default, public launch edition two, and installed launch edition
three checksum profiles keep their published bytes and interpretation. General
registry negotiation is introduced by a distinct profile/format selection.
Adding an explicit schema selection to an old profile cannot silently relabel
its artifacts or turn old evidence into new qualification.

Stored provider selection comes from the stored execution binding. A changed
current command-line default does not select an implementation for legacy state.
Unknown authentic legacy implementation identity refuses. Conversion is a
separate named operation with declared loss and an immutable conversion record.

## Meaningful conformance cases

The implementation acceptance map should link each concrete case to its test,
installed implementation/configuration identities, actual evidence scope, and
known exclusions. Portable tests establish record and policy behavior. Actual
endpoint tests establish public negotiation and source-installed interactions.
Neither automatically qualifies live timing or exact continuation.

| Requirement | Portable/policy case | Actual public endpoint case |
| --- | --- | --- |
| EXT-1 | Foreign namespace, core redefinition, incomplete schema/specification, unbounded or cyclic dependency closure refuse | Required unauthorized declaration refuses before realization/companion spawn |
| EXT-2 | Unselected optional offer contributes no selected binding identity; required unknown declaration refuses | Optional unsupported offer leaves actual model/bytes/permissions unchanged; required offer creates no native realization |
| EXT-3 | Correct ID with wrong version/schema digest refuses; unrelated success cannot select another scope | Provider omits or changes explicit selected schema/version; controller refuses before native effects |
| EXT-4 | Control/guest/port/state compatibility are checked independently | Successful native checksum work does not enable pause, capture, or detailed CPU fidelity |
| EXT-5 | Changed future-state definition creates a different binding; old capture rejects relabeling | Existing realization cannot switch declaration while retaining original world/operation identity |
| EXT-6 | Stored authentic implementation wins over current defaults; unknown stored implementation refuses | Restart uses the saved provider family or refuses before preparation |
| EXT-7 | Statement includes exact bindings, exercised domains, scope, exclusions, and immutable case identities | Actual negotiated source/profile is named; parser and boot results cannot become preservation qualification |
| EXT-8 | Resume refuses missing selected optional feature, changed schema, or weakened guarantee; originals remain retained | Genuine surviving child reconnect with changed selection refuses and cannot resubmit original native work |
| EXT-9 | Additional profile needs its full explicit failure/ownership/timing/state/security definition | Unregistered remote transport, migration, physical rollback, or conversion profile cannot appear as core support |

Adversarial resource tests exercise limits before native effects and separately
exercise failed host bookkeeping after a genuine accepted input. The latter
must remain Unknown with the original input, peer receipt, payload, provenance,
cut, sequence, and native resources retained. It cannot be reported as an
ordinary no-effect capacity refusal.

## Implementation order

1. Add isolated portable declaration/selection records, checked identities,
   closure limits, and negative tests. Keep module registration coordinated.
2. Add an installed empty-by-default namespace/semantic registry and immutable
   selection snapshot. Prove unknown/default refusal before enabling dispatch.
3. Add explicit hello selection and exact resume snapshot matching. Preserve
   all existing baseline/private profile bytes and original fencing semantics.
4. Add selected per-location semantic validation and world-binding admission;
   replace blanket refusal only for the exact installed selected scopes.
5. Add the distinct actual public provider profile and required/optional,
   altered-schema, wrong-scope, resource, and reconnect probes.
6. Add persisted-world/compatibility and conformance publication integration.
   Register external definitions only under configured trust and genuine
   implementation qualification.

The public installed CNP factory, accepted-input uncertainty tests, authentic
cross-hop lineage, and source-qualified reconnect remain separate executable
integration stages. The registry must integrate with those original ownership
and admission boundaries rather than provide an alternate effect path.
