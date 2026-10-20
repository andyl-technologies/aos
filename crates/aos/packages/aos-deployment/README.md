# AOS deployment execution

`aos-deployment` evaluates authenticated AOS module inputs and executes bounded,
journaled activation transactions. Package management, boot configuration, and
other deployment callers provide scope, source authorization, and artifact
admission through explicit values and traits.

The crate owns pure evaluator subprocess construction, temporary immutable
source views, checked store document reads, NAR/reference verification, store
retention, handler transport, and durable generation journals. Portable
schemas live in `aos-deployment-format`.

It does not depend on package installation, registry authoring, or profile
publication. Those callers provide policy and publish completed generations.
Existing process protocol and persisted schema identifiers are preserved.
