# Security policy

This policy covers the AOS operating system, packages, build and release
tooling, `aos`, `apm`, `apr`, AOS Hub, and Crucible, including their bundled
dependencies and integrations.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/andyl-technologies/aos/security/advisories/new)
to report a suspected vulnerability. Anyone may submit a private report.
Please keep undisclosed vulnerability details out of public issues, pull
requests, and discussions.

Include what you know:

- The affected component, release version or source revision, and platform.
- The security impact, expected behavior, and observed behavior.
- Reproduction steps or a minimal proof of concept.
- Relevant configuration, logs, and any known workaround.

Remove credentials, private keys, personal data, and unrelated sensitive
information from attachments. An incomplete report is welcome; you do not
need a fix or a confirmed root cause to contact us.

Anyone may open public issues for ordinary bugs and feature requests. External
contributions are currently disabled, and only project contributors may open
pull requests. Reporting a vulnerability does not require a contributor
agreement. Project contributors handle remediation under the
[contribution requirements](CONTRIBUTING.md).

## Supported versions

AOS is an [early preview](docs/users/aos/support-status.md). Release support is
defined by the [release-train support policy](docs/maintainers/qualification.md#release-train-support)
and published in the signed registry's support metadata:

- A stable release belongs to its `major.minor` train. By default, a train
  remains supported until two newer stable trains exist.
- An explicit support end date overrides the rolling rule. Long-term support
  (LTS) trains must state an end date.
- The `edge` channel has no production support promise.

The published support metadata determines which release trains receive
updates. Please report suspected vulnerabilities even if you are unsure
whether the affected version is supported. Identifying affected versions
helps us assess exposure in supported releases and current development.

## Handling and disclosure

Maintainers review private reports, ask for additional information when needed,
and coordinate remediation and disclosure with the reporter. For
vulnerabilities in bundled dependencies, we coordinate with upstream
maintainers as appropriate.

Please coordinate public disclosure with us so users can obtain a fix or
mitigation. We publish confirmed vulnerabilities through
[GitHub security advisories](https://github.com/andyl-technologies/aos/security/advisories)
when remediation is available, explaining affected versions and any available
fixes or mitigations. We offer public credit with the reporter's consent.

## Security research

Test only on systems you own or have permission to test. Minimize disruption
and access to data, and stop testing if it exposes someone else's sensitive
information. Share only the evidence needed to explain the vulnerability
through the private reporting channel.

## Security guidance

- [Security hardening](docs/users/aos/security-hardening.md) describes host
  security settings and their current limits.
- [Package sandboxing](docs/users/aos/package-sandbox.md) explains service
  confinement and permissions.
- [The AOS trust model](docs/maintainers/trust-model.md) describes signing
  authorities, release trust, and compromise response. Checked-in Secure Boot
  keys are public test fixtures; canonical production publication remains
  disabled until its launch gates are complete.
