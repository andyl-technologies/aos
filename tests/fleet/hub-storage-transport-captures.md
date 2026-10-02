# OCI and placement-copy transport captures

The selected External fleet now retains compact application controls in a
separate precreated `0600` log beside each existing private body observer.
Bearer, cookie and CSRF headers are not selected. Arbitrary query strings and
their ingress compacts are omitted; their records remain explicitly unsupported.
Only the closed OCI upload selectors are retained. Raw header values and bodies
remain private, while summaries contain file hashes and measured byte counts.

Native emits `external_copy_authenticated` and `oci_projection_authenticated`
only after their existing reply authenticator succeeds. Version 2 receipts bind
the actual offered request and consumed reply hashes and lengths to the original
plan and a fresh 128-bit `transportCallId`. That ID is sent in the observational
`x-aos-storage-call-id` header; it grants no authority and changes no signed body.
Invalid MACs, expired replies, unread HTTP refusals and cancellation emit no
success receipt. Request bytes are offered application bytes, not evidence of
delivery or TLS billing.

The controller retains a bounded journal window under the unchanged running
Native PID, start time and installed executable. It joins both independent
proxy bodies and request/reply MAC commitments to those receipts. Header equality
and successful HTTP status alone are insufficient. The retained canonical Copy
request is the exact original/source/placement/object context; its closed codec
must still match the final compiled runtime.

Each join requires the exact call ID on both independent proxies and exactly one
corresponding successful receipt. Identical genuine replay bodies may join only
under distinct actual call IDs. Missing, reused or substituted call IDs and
multiple matching receipt events remain unresolved. Their actual completion
timestamps remain retained in the raw journal; a success cannot authenticate
another identical call that later failed.

OCI projection signatures use their own `x-aos-oci-projection-signature` header,
retained separately from the storage-work signature. Only the existing exact
projection authenticator can emit its successful receipt. This transport join
still supplies no current actor, purpose, provider or placement conclusion.

The header parser streams the retained private file one row at a time. Its
204,704-record ceiling allows two selected stock publications, each containing
12,535 metadata and three large originals, an observation allowance of eight
records per original, and 4,096 additional rows. This is a parser budget, not a
protocol guarantee or measured call budget. Every row is retained; excess,
incomplete or unsupported observations cannot establish complete coverage.

Raw logs remain bounded to 512 MiB and each input row to 48 KiB. Retained join
summaries are separately bounded to 204,704 entries, six compact references per
entry, 2 KiB serialized per entry and 256 MiB serialized in total. Python object
overhead is additional and has not been measured; these are representation
bounds, not a claim about exact process RSS. No second complete raw-log JSON
buffer is built. Overflow refuses the assessment and leaves its raw capture.

These transport joins do not prove current SQL actor authorization, a reviewed
purpose artifact, provider object ownership or a complete provider partition.
Those fields and `nativeBulkBytes` remain null. Actual provider observations keep
known and unknown request bodies separate, with measured reply bytes and caller
groups. Copy progress/part sizes are never substituted for Native byte counts.

The existing APR publication assessment is unchanged. OCI authorize-final,
bootstrap/blob controls, unknown routes, material-bearing controls, partial
captures and missing independently offered ingress headers remain unresolved.
The changing External OCI producer must supply its own exact source-bound
authenticated originals and replies before a final codec can cover its phases.
Historical observation binaries and their source scopes are not relabeled.

## Local gates

Run the parser tests with the selected AOS Python package:

```sh
<aos-python>/bin/python3 tests/fleet/_hub-storage-capture-tests.py
```

Render the exact Nix format and use an already installed AOS Nginx package:

```sh
<aos-nix>/bin/nix eval --impure --raw --expr \
  '(import ./tests/fleet/_hub-protected-header-format.nix) "controlled_headers"' \
  > /tmp/controlled-header-format.conf
<aos-python>/bin/python3 tests/fleet/_hub-protected-header-local.py \
  --nginx-bin <aos-nginx>/bin/nginx \
  --format-file /tmp/controlled-header-format.conf \
  --output-root /tmp/fresh-controlled-header-run
```

This local process gate checks only capture formatting, private log mode and
credential/query omission using controlled headers. The Native HTTP tests use
real local exchanges and the existing authenticator. Neither gate qualifies a
Worker, provider, fleet workload, current authority or Native bulk zero. Final
source/console/package/process binding and actual complete window joins remain
required before any such assessment.
