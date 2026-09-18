# Traefik dashboard dependency sources

`pnpm-lock.yaml` pins the dashboard dependencies for Traefik 3.6.7. It was
imported from that release's `webui/yarn.lock` with the AOS-built pnpm 12.3.4
using `pnpm --pm-on-fail=ignore import`. Importing also resolves pnpm's peer
dependency graph, so this lock is a separately reviewed build input.

The fixed-output source fetch uses this lock without lifecycle scripts or
pnpm hooks. `remove-precompiled.py` removes native executables, libraries,
archives, and WebAssembly payloads and records their relative paths in
`removed-precompiled-files.json`. The pure dashboard build supplies both
esbuild versions and Rollup's native parser from AOS source derivations.

For an upgrade, import the new upstream lock using the AOS pnpm package,
review the dependency changes, update the native tool source pins to match,
and refresh the fixed-output source hash. Verify the removal inventory and
the full TypeScript and Vite build before accepting the result.
