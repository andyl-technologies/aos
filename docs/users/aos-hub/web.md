# Use the AOS Hub web interface

The Hub web interface is rendered on the server. Its browse and management
forms work without JavaScript; passkey sign-in uses a small first-party script.
Public registry pages can be read anonymously. Account, organization, project,
registry, and instance changes require a signed-in account with permission on
the relevant scope.

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
| Registry health | `/acme/cdn/-/health` |

The `/-/` segment keeps human-facing routes separate from the machine facade at
the registry root. Git objects, AOS releases and channels, Nix cache metadata,
and NARs therefore keep their native paths.

## Sign in and administer a Hub

Open `/login`. A deployment may offer password, passkey, magic-link, or OIDC
sign-in depending on its configuration. The browser session is separate from
the bearer tokens used by API clients.

After signing in, use:

- `/-/account` for the current account;
- the organization and instance settings under `/-/` for administrative work;
- `/<org>/<registry>/-/settings` for registry configuration.

The console uses the same IAM roles and scope inheritance as the API.
Permissions inherit down the scope tree, from the instance to an organization,
project, and registry. Roles are task-oriented rather than a simple ladder:
Admin manages organization settings, while Maintainer owns publishing,
channels, and keys. Owner has both sets of permissions; Developer and Viewer
are narrower roles.

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
