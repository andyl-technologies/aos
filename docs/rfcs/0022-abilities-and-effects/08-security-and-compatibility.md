# Admission, provenance, and compatibility

A native graph describes desired behavior. It is not an authority to download
or execute arbitrary artifacts. The package caller authenticates the selected
release or image and admits exact immutable sources, payloads, and handlers
before the runtime prepares a generation.

Module provenance comes from the resolver and module engine. Package modules
cannot establish ownership by assigning their own package name or diagnostic
metadata. Shared extensible options still merge through their declared module
types; unrelated packages cannot silently replace another package's private
configuration. Runtime and documentation projections preserve declared owners.

The restricted evaluator imports retained sources by exact identity, uses fixed
inputs, disables import-from-derivation, and produces data. Process dispatch is
a separate boundary. Transport limits input and output, duration, and cancellation.
The checked graph rejects malformed references, unknown handlers, incompatible
results, and cycles before mutation.

Original publication or image receipts remain the source of admission. A local
receipt, quoted descriptor, or path name cannot make itself a trust anchor.
Evidence distinguishes authored desired state, attempted dispatch, completed
results, and independent observations of the target.

A durable intent without a completed result requires handler observation.
An indeterminate observation stops recovery. Failed reloads, cancellation, and
process loss must not be converted into successful activation or an assumed
safe retry. Persistent resources need explicit retirement.

Wire readers reject unknown schemas and unsupported fields. This PR performs
an immediate cutover: superseded in-PR catalogs, parsers, and execution adapters
are removed with their callers. There is no compatibility layer between draft
implementations. Future released-format changes require their own explicit
compatibility design.
