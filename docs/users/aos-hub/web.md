# Use the AOS Hub web interface

The Hub has two browser surfaces. Public registry browsing and the login,
account-security, invitation, and device-approval ceremonies are rendered on
the server. Authenticated resource management uses the first-party AOS Hub
console and requires JavaScript. Public registry pages can be read anonymously.
Account, organization, project, registry, and instance changes require a
signed-in account with permission on the relevant scope.

## Browse published data

Registry URLs use the organization and registry name as a slug. For a registry
named `cdn` in the `acme` organization:

| Page | Path |
| --- | --- |
| Registry home | `/acme/cdn/` |
| Packages | `/acme/cdn/-/packages` |
| Package detail | `/acme/cdn/-/packages/<name>` |
| Channels | `/acme/cdn/-/channels` |
| Channel detail | `/acme/cdn/-/channels/<name>` |
| Releases | `/acme/cdn/-/releases` |
| System images | `/acme/cdn/-/images` |
| Registry health | `/acme/cdn/-/health` |

Packages, Docs, Images, and Containers show one exact release at a time. The
release selector offers each channel's current target, the newest releases,
and the selected release; the Releases page lists every publication. The jump
field accepts a version, a commit, or a channel name such as `stable` and
redirects to the exact version, so a copied link never drifts when a channel
moves. Unknown releases are not found rather than falling back to another
release.

The Docs page is a configuration browser. The tree on the left is the scope:
expand branches lazily or filter the loaded labels. The reader lists the
current scope's children with their types and descriptions, or every option
beneath it as dotted paths with **Options**, fifty per page.
Opening a documented option shows its type, default, example, allowed values,
activation, and declaration. With JavaScript enabled, choosing a scope swaps
the reader in place and keeps the tree expanded; every link also works as an
ordinary page load.

The `/-/` segment keeps human-facing routes separate from the machine facade at
the registry root. Git objects, AOS releases and channels, Nix cache metadata,
and NARs therefore keep their native paths.

The Images page presents signed release encodings as end-user disk downloads,
including architecture, format, compatible target, size, checksum, and
verification state. Public downloads may use a ready CDN or direct delivery
route. Private downloads stay on the Hub origin so the signed-in browser can
authorize the exact disk bytes with its session cookie.

The Releases page opens with a support board: one tile per supported train,
newest train first, showing the train's `major.minor`, its LTS marker, its
newest release (a candidate counts for its train), "Until" and the end date
when the registry states one, and the channels targeting it. Trains that no longer
receive updates are not listed, and a train within ninety days of its end date
is highlighted. The registry's committed `[support]` policy decides; without
one, the newest two trains and any channel-targeted train count as supported.
Filters narrow the directory by major version, minor version, and status
(stable, candidate, edge, other prerelease, or long-term support when the
registry marks LTS trains).

A release page shows its notes, contents, and rollout. When the registry
serves a public release record for it, the page adds a Qualification section:
the result and admission time, the release class, the policy and authority,
the train's support statement at release, a table of every claim with its
required and achieved assurance, and provenance digests. The Hub shows the
section only after verifying the record's signed qualification envelope
against its trusted keys; the served registry remains the authority.

A channel page shows the target release, the minimum allowed release, and the
share of the 256 rollout buckets assigned, then the rollout bar and a
colour-coded bucket map. Enter a host's bucket to see which release it gets.

## Sign in and administer a Hub

Open `/login`. A deployment may offer password, passkey, magic-link, or OIDC
sign-in depending on its configuration. Settings pages keep their headings
short; the `?` mark beside a section title opens its explanation on hover,
focus, or click. The browser session is separate from
the bearer tokens used by API clients.

After signing in, use:

- `/-/account` for the current account;
- the organization and instance settings under `/-/` for administrative work;
- `/<org>/<registry>/-/settings` for registry configuration.

Organization resource inventories keep creation separate from browsing:
`/-/org/<org>/projects/new`, `registries/new`, `caches/new`,
`bindings/new`, `domains/new`, `network-policies/new`,
`endpoints/new`, and `gateways/new` open focused reviewed-
creation workflows below the same organization root. The inventory pages link
to those routes and do not mix full create forms into the resource list.
Deployment-wide domain, network-boundary, delivery-endpoint, and
storage-gateway inventories use the same pattern below `/-/instance`, with a
`new` route below each collection. A create action is shown only when the live
scope grants the API permission required by that resource; organization
creation remains governed by the instance signup policy.

The management console uses the same `aos.hub.v1` Connect API, reviewed
plan/apply mutations, and IAM checks as the CLI. It exchanges the HttpOnly
browser session and page CSRF proof for a five-minute bearer held only in
memory; it never stores that bearer in local storage or IndexedDB. Canonical
management deep links therefore load the same client application, while login
and account-security ceremonies remain ordinary server-rendered pages.

The console uses the same IAM roles and scope inheritance as the API. Its
navigation is filtered using live permissions evaluated by the Hub for the
exact current resource; typing a sensitive deep link directly does not reveal
the page when that permission is absent.
Permissions inherit down the scope tree, from the instance to an organization,
project, and registry. Roles are task-oriented rather than a simple ladder:
Admin manages organization settings, while Maintainer owns publishing,
channels, and keys. Owner has both sets of permissions; Developer and Viewer
are narrower roles.

Registry and cache settings start with effective configuration. **Delivery**
shows selected client destinations and offers a [coordinated setup workflow](delivery.md).
**Storage & replicas** shows effective read and write locations before offering
storage setup and replication. Advanced policies and diagnostics load when
opened; per-location controls retain desired state, controller observations,
and reviewed promotion, drain, and deletion. The request
explainer tests an absolute URL, optional machine-path override, and `web`,
`git`, or `nix_cache` access class against the live simultaneous route set. The
object-presence lookup shows the reported digest, size, and state at every
placement. Cache administrators with GC execution authority can review a
physical placement eviction from the placement card; this is distinct from
logical cache garbage collection and starts a durable evacuation operation.

The cache **Objects** page accepts a canonical machine path and exact file. The
Hub admits either a short-lived direct-origin upload or an authenticated
same-origin proxy upload. Large files automatically use the Hub's multipart
protocol, and a failed part aborts the durable upload. The browser never sends
its Hub bearer to a direct storage URL.

The organization's **Members** page includes member and invitation inventory.
**Invite a member** creates a reviewed pending invitation and shows its
acceptance link after apply; it does not pre-create an account or
membership. Deliver that link only to the intended email. The invitee signs in
as the exact matching address. The first visit exchanges the URL credential
for a short-lived, HttpOnly browser handoff and redirects to a clean URL before
showing navigation or login. Password, magic-link, passkey, and SSO login all
return to that clean acceptance page. The invitee reviews and accepts it; the
Hub then consumes the invitation and creates the membership atomically. Member
managers can cancel a pending invitation from the same page. Accepted,
cancelled, and expired invitations remain visible as history.

The organization **SSO** page manages one OIDC identity provider and its email
domains. Provider reads are redacted to a “client secret configured” state.
Saving or removing a provider first shows an immutable effects review and then
applies the exact reviewed revision. A blank client-secret field preserves the
current credential; the explicit clear checkbox removes it.

Claiming a domain returns the TXT value to publish. **Verify DNS** also uses a
reviewed plan and performs the DNS lookup in the Hub; it cannot mark a domain
verified merely because an administrator clicked the button. Only a verified
domain participates in email-first SSO routing. Domain release is separately
reviewed and stops that routing. Rotating a challenge returns the domain to
pending state until the new value is published and verified.

## Browse a binary cache

Cache slugs share the top-level URL namespace with registries:

| Page | Path |
| --- | --- |
| Cache home | `/<cache>/-/` |
| Objects | `/<cache>/-/objects` |
| Object detail | `/<cache>/-/objects/<store-hash>` |
| Transitive closure | `/<cache>/-/closure/<store-hash>` |

A public cache also exposes its object list at `/<cache>/-/api/objects`.

## Use the simple JSON views

Public-only, read-only JSON views are available alongside the browse pages:

```text
/<flat-slug>/-/api/registry
/<flat-slug>/-/api/packages
/<flat-slug>/-/api/packages/<name>
/<flat-slug>/-/api/channels
/<flat-slug>/-/api/releases
```

These routes never use a browser session or bearer token to reveal non-public
data. The convenience router currently accepts single-segment slugs; use the
unary API for canonical organization/registry paths such as `acme/cdn`. Use
these routes for small read integrations and the [HTTP API](api.md) for
authenticated visibility, writes, or stable service methods.

## Authentication behavior

- Password sign-in is enabled by default and can be disabled in instance
  settings.
- Passkeys provide usernameless WebAuthn sign-in. They require the small
  first-party browser script mentioned above.
- Magic links are single-use and expire after 15 minutes. Native deployments
  currently log them; Worker deployments need Email Service or an HTTP relay
  for delivery.
- OIDC is configured per organization and uses authorization code with PKCE.
  The current implementation accepts RS256 ID tokens.
- Browser sessions use a secure, HTTP-only cookie. The defaults are seven days
  idle and 30 days absolute, with a 15-minute reauthentication window for
  sensitive work; the absolute lifetime cannot exceed 30 days.

The `aos hub login` device-code flow uses the same identity and authorization
state as browser sign-in; see the [CLI guide](cli.md).
