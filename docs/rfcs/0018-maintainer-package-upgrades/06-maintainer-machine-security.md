# Maintainer-machine security

## Threat model

The local workflow deliberately retrieves and executes new upstream content,
then may expose attacker-controlled material to a model. Treat all of these as
untrusted:

- provider and Repology responses;
- release notes, issues, commits, tags, archives, checksum files, patches, and
  generated manifests;
- configure/build/test programs and output;
- model-generated explanations and patches;
- PR/review/comment text when inspected by a later run;
- cache data not revalidated against its content identity.

Threats include upstream compromise, typosquatting or project-ID collision,
mutable tags/artifacts, malicious build scripts, prompt injection, credential
exfiltration, arbitrary local file access, Git ref manipulation, cache
poisoning, dependency/feature/test removal, forged evidence, and accidental use
of release authority.

The tool is trusted AOS maintainer software. It must assume the source,
subprocess, and model sides can be hostile and mediate every capability they
receive.

## Local process boundaries

```text
interactive maintainer
        |
        v
trusted `aos maintain` parent
  |                |                              |
  v                v                              v
discovery      model client             local confinement backend
public net     inference only       candidate eval/materializer/tools/tests
  |                |                    private fs/process/net/credentials
  +----------------+------------------------------+
                         |
                  typed bytes/results
                         |
                         v
                mutation/evidence verifier
                         |
                         v
                 isolated Git worktree

separate explicit `commit` / `publish-pr` invocation
uses maintainer Git/signing/remote authentication
```

No untrusted child receives the maintainer's general environment or home
directory. Environment filtering alone is not the boundary: candidate
evaluation, networked materializers, agent tools, builds, and tests run inside a
verified local confinement backend before any commit, signing, or remote-auth
phase can begin.

## Mandatory local confinement backend

Environment variables, temporary directories, and selected file descriptors do
not stop a same-UID process from opening the maintainer's files, `/proc`, user
sockets, or sibling processes. A conforming backend therefore enforces an OS
boundary and owns/reaps the complete worker process tree.

The initial Linux backend must provide:

- a separate subordinate UID plus private user, mount, PID, IPC, UTS, and
  network namespaces;
- a minimal read-only input view and writable scratch/output mounts with no
  maintainer home, Git common directory, state directory, agent/signing sockets,
  or unrelated paths;
- a private `/proc`, no host device access except an explicitly planned KVM
  capability, no privilege escalation, and a bounded syscall/device policy;
- cgroup resource limits and pidfd/cgroup-based termination/reaping before any
  privileged local phase;
- default-deny network; networked materializers receive only a constrained
  egress proxy/namespace whose destination and redirect policy is enforced
  outside the worker;
- a private Nix evaluation/build context and store/daemon boundary, optionally
  reading a verified cache, rather than arbitrary access to the maintainer's
  host Nix daemon socket.

On Darwin, where an equivalent combination cannot be enforced for arbitrary
upstream code, the required backend is a disposable local VM with the same
mounted-input, egress, process, credential, and teardown contract. A platform
without a verified backend can still run read-only trusted discovery and plan
commands, but candidate evaluation, networked materialization, agent tools, and
tests are action-required.

The backend is a local tool capability, not a resident process. `aos maintain`
creates it for an operation, imports only typed results, terminates/reaps it,
and verifies teardown before enabling commit signing or remote authentication.

## Candidate Nix evaluation

The Nix builder sandbox begins after evaluation, so it does not protect the
maintainer from candidate-controlled `builtins.readFile`, environment access,
fetch-at-evaluation, or import-from-derivation behavior. Every candidate
evaluation therefore runs inside the confinement backend with:

- an empty allowlisted environment and explicit system/target values;
- pure and restricted evaluation;
- imports restricted to the candidate checkout and declared store inputs;
- import from derivation disabled;
- no public network;
- strict time, memory, output, and evaluation-depth limits.

The protected base inventory can be evaluated by the trusted parent to create a
plan. After any candidate source edit, only the confined evaluator produces the
candidate inventory, derivation graph, or test plan. The parent treats those
bytes as untrusted and validates them through the closed Rust model.

Networked package-manager materializers have kind-specific policies. Cargo, Go,
and npm adapters deny lifecycle/build scripts during dependency acquisition.
Bazel repository rules and any adapter that executes fetched logic require the
full confinement/egress boundary and explicit output contract; an adapter that
cannot enforce those properties remains unavailable/manual.

## Credential phases

Separate credentials by command:

### Discovery

May use a read-only provider token when required for rate limits. The token is
read by the trusted provider client, never copied into request evidence, logs,
cache bytes, source builders, agent tasks, or child environments.

### Agent inference

The trusted local model adapter holds only the configured inference credential
in the parent process. The model receives task content and returns structured
tool calls/results; the subprocesses implementing tools do not inherit the
credential. A local model needs no credential.

An adapter that can expose its authentication file/environment to model-driven
filesystem or shell tools does not satisfy this RFC and must run in no-tool mode
behind the AOS capability interface.

### Commit signing

Only `aos maintain commit` may invoke the maintainer's configured Git signing
mechanism. It runs after the patch is accepted and shows the exact tree and
message. Agent, source, materialization, and test processes cannot reach the
signing agent or device.

### Remote Git and PR publication

Only `aos maintain publish-pr` reads or invokes remote Git/GitHub
authentication. It has no path for merge, tag, release, package publication, or
RFC-0017 signing credentials. Authentication values are never written to run
state or passed to hooks, builds, tests, or the agent. The one-shot publisher
uses an empty hooks path, sanitized Git configuration, exact remote/refspec,
expected remote head, and explicit confirmation. Repository protected-branch
rules remain the backstop when a maintainer credential itself has wider access.

Maintainers should not run the main update loop from a shell that globally
exports sensitive credentials. The tool strips a denylist and constructs an
allowlisted environment for every child regardless.

## Environment and filesystem isolation

Every untrusted worker inside the confinement backend also receives:

- an explicit executable from the AOS environment;
- an allowlisted environment with controlled locale, temporary/state/cache
  paths, and no general `HOME` unless the typed operation requires a synthetic
  empty one;
- only the file descriptors and paths required by the operation;
- CPU, memory, process, output, disk, and wall-clock limits;
- no SSH agent, GPG agent, cloud metadata credential, GitHub token, release
  secret, or unrelated socket.

The agent's file tools operate on a bounded disposable view, not the real Git
worktree or repository control directory. The mutation gateway applies its
patch after validation.

Nix builds use the confined private Nix context plus AOS's existing package
sandbox and declared dependencies. No package build reads host tools, host
`/bin`/`/usr/bin`, nixpkgs, the maintainer home, or network. Tests needing KVM
receive only the documented device capability and test inputs, not arbitrary
host mounts or credentials.

Network-enabled source or generated-dependency preparation uses a fresh bounded
worker plus an externally enforced destination/redirect policy. Its output
becomes a fixed content-addressed input for the network-disabled package build.
It does not grant ordinary phases network access.

## Prompt injection boundary

Release notes, source files, patches, build logs, and provider metadata can tell
the model to ignore instructions or request secrets/tools. They are data, never
control messages.

OWASP states that prompt injection has no foolproof model-level prevention and
recommends constrained behavior, segregation of external content, least
privilege, deterministic output validation, and human approval. See
[LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
and [LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).

Required controls are therefore external to the prompt:

- closed task and result schemas;
- bounded external-content fields clearly separated from policy;
- typed tool allowlists;
- read/write path capabilities;
- no general shell or Git tool;
- secret-free tool environments;
- deterministic patch and semantic-diff validation;
- maintainer approval for scope expansion and candidate acceptance;
- complete AOS tests that do not trust model claims.

Free-form agent output cannot alter plan state, add paths, consume more budget,
or mark a gate successful.

## Source assurance

Hashing newly downloaded bytes is necessary but does not prove that the first
download was authentic. The trusted resolver enforces each component's origin
and assurance policy before any source reaches a build or agent.

Record requested/mirror/final URLs, redirects, content digest/size, exact
upstream release identity, and checksum/signature/provenance result. Quarantine
same-identity byte changes, mirror disagreement, unexpected redirects, missing
previously required signatures, and mapping conflicts.

The recorded outcome distinguishes independently `verified-authentic` sources
from `origin-integrity` sources that rely on an allowlisted HTTPS origin plus a
new digest. Missing or failed required evidence is `unknown`/`failed`, not an
authenticity pass. A unit may permit origin-integrity candidate preparation only
with its explicit risk and human source-review gate.

No agent explanation can override quarantine. A maintainer must explicitly
accept new upstream identity/policy in a new plan generation.

## Git and worktree protections

- Resolve the exact main checkout and Git common directory before work.
- Create only a named update worktree under the selected local state root.
- Validate branch names against
  `dplecki/upgrade-<campaign-slug>-<target-summary>` policy.
- Record expected HEAD and tree before each mutation.
- Never use an unresolved environment variable, broad glob, repository root, or
  home directory as a deletion target.
- Never reset, clean, checkout over, or force-push unrecognized human work.
- Reject symlinks escaping allowed roots, submodules, special files, unexpected
  modes, and case/path normalization collisions.
- Do not execute repository hooks while applying an agent patch.
- Display exact worktree/branch/evidence targets before cleanup.
- Require confirmation before deleting a worktree with uncommitted or
  unretained state; default is refusal.

The tool treats `.git`, `.github`, contributor-authorization policy, release
policy, signing configuration, and maintainer-tool policy as outside the agent
write surface. A package update needing one of those changes becomes a separate
human-authored project.

## Subprocess and log handling

Use argument arrays, not interpolated shell strings. Validate package, suite,
attribute, branch, path, URL, and target values before passing them to Nix, Git,
or a shell phase. Shell output is data and never fed back as arguments without
typed parsing.

Bound stdout/stderr bytes and line lengths. Preserve full allowed logs locally
when useful, but create sanitized excerpts for agent tasks and PR output. Redact
known credential formats and sensitive headers before persistence; prevent
debug output from dumping process environments or authentication configuration.

An over-limit log terminates or truncates the observation with an explicit
status. It cannot exhaust the maintainer disk or silently lose the fact that
validation output was incomplete.

## Cache safety

- Address immutable response/download bytes by digest.
- Validate size, digest, schema, and parser limits on every read.
- Keep mutable request indexes separate from immutable bytes.
- Use atomic writes and restrictive permissions.
- Do not put Git, inference, signing, or publication credentials in cache keys,
  request records, or metadata.
- Do not let an agent write cache objects or indexes.
- Treat cached artifacts as untrusted until the current plan verifies their
  expected content identity and source policy.
- Never substitute candidate update outputs into RFC-0017's trusted release
  cache solely because a local update build passed.

## Supply-chain claims

SLSA distinguishes hermeticity, isolation, and authenticated provenance; an
external input remains untrusted even when its origin is recorded. The local
tool should use those concepts without claiming a SLSA build level that the
maintainer-machine boundary does not establish. See the
[SLSA v1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements)
and [build provenance](https://slsa.dev/spec/v1.2/build-provenance).

The update evidence states what was observed, changed, and tested. It does not
claim upstream code is safe, establish release provenance, or replace human
review.

## Contributor authorization and authorship

The maintainer who accepts and commits the final tree uses their stable Git
identity and follows the existing contributor-authorization path. The tool does
not create an alternate automated author identity, impersonate a maintainer, or
insert AI attribution.

Before `publish-pr`, verify as much as local state permits:

- configured author/committer identity;
- required commit signature;
- no disallowed attribution/trailer text;
- expected base and branch namespace;
- clean final-gated head;
- required maintainer/specialist acknowledgments represented in evidence.

These are identity/signature preconditions, not contributor authorization. The
authoritative contributor-authorization check uses private records in the
repository review path and cannot run locally. `publish-pr` records it as
`pending-remote`; a later foreground observation may record its exact-head
result, and indeterminate/unavailable remains action-required. Private employee
or agreement records never enter the checkout or update evidence.

QEMU-side work additionally requires the human legal-name DCO sign-off. The
tool does not add it automatically. It pauses for the authorized human to
review, commit/sign off, and then reruns validation on that exact commit.

## Publication safety

`publish-pr` can push only the run's recorded `dplecki/upgrade-*` branch and
create/update a matching PR against the configured base. It refuses:

- a non-final-gated head;
- a remote head that differs from its expected value;
- tags, protected branches, force pushes, merge operations, releases, or
  package publication;
- PR text or commits containing disallowed attribution;
- unexpected extra commits or semantic/filesystem changes;
- missing required human action.

The command displays all remote effects and requires explicit confirmation. A
network/API failure leaves local state intact and retryable.

RFC-0017 release commands and credentials are not callable from update or agent
operations. After human review and merge, release tooling begins from the
protected commit under its own runbook.

## Security acceptance tests

Before agent-assisted write mode is enabled, prove:

- the Linux namespace/UID/cgroup/egress backend and Darwin local-VM backend fail
  closed when a required isolation primitive is unavailable;
- candidate Nix evaluation cannot read undeclared host paths/environment, fetch
  at evaluation, or use import from derivation;
- prompt injection in metadata, release notes, source, or logs cannot request a
  denied tool, path, secret, Git action, or successful gate;
- agent tools cannot read `.git`, the general checkout, maintainer home,
  environment secrets, agents/sockets, or local run credentials;
- Nix builds remain network-disabled and hermetic;
- network materializers cannot reach undeclared destinations or retain
  credentials in outputs;
- the complete worker process tree is terminated and reaped before signing or
  remote authentication becomes available;
- expected-value, out-of-scope, symlink, submodule, mode, binary, oversized, and
  path-traversal patches are rejected;
- human worktree changes stop automation rather than being overwritten;
- corrupt/truncated/reordered journal or cache inputs fail closed;
- interrupted effects resume from verified boundaries without duplicate Git
  writes;
- unavailable tests remain action-required;
- commit/push use an empty hooks path, and `publish-pr` cannot force-push, tag,
  merge, release, or call publication commands;
- contributor authorization and QEMU DCO requirements cannot be bypassed;
- logs and final PR text contain no credentials, raw private prompts, or
  prohibited attribution.
