# tests/fleet/apm-e2e.nix — End-to-end fleet test for apm + registry + cache.
#
# Two machines:
#   server (192.168.50.11): aos-registry-server package — git daemon on
#                            :9418, aos serve on :15000. Bootstrap socket
#                            on /run/aos-registry-server/bootstrap.sock.
#   client (192.168.50.10): relies on modules/base/apm.nix for `apm`
#                            and friends.
#
# The test drives the full apm flow over the fleet's multicast L2:
#   1. Server stands up; both units active; cache responds.
#   2. Server-side setup: registry repo created, fake testpkg-1.0
#      synthesised in $AOS_ROOT/store, NAR pushed to the cache,
#      package TOML written + committed in the registry, registry.toml
#      points `[[caches]]` at the server's aos serve.
#   3. Client: `apm registry add git://server:9418/test-reg`.
#   4. Client: `apm update` — git fetch pulls the TOMLs.
#   5. Client: `apm install testpkg` — NAR is fetched from the cache
#      and the store path materialises.
#
# `testScript` is Python (Machine API). Pre-rendered TOMLs are read
# from their store paths via `pathlib.Path("${drv}/file").read_bytes()`,
# base64'd, and decoded on the guest — avoids any quote-escaping for
# the file bodies. The seeding block (step 3) runs as one big
# `server.succeed(textwrap.dedent(f"""..."""))` so the shell vars
# (JWT, NAR_HASH, etc.) stay in scope across the dance.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  tomlFmt = lib.formats.toml {inherit lib pkgs;};

  # server-test bundles the guest agent and the CLI tools fleet scripts need
  # (git/sqlite/socat to hand-seed the registry, curl/jq to probe it) — image
  # slimming keeps those out of the production server. The registry machine
  # additionally re-bundles aos-registry-server; the client just needs the
  # tools (systems.server-test).
  serverWithRegistry = mkSystem [
    ../../systems/server-test.nix
    {aos.packages.aos-registry-server.bundle = true;}
  ];

  # Stable test values. The 32-char store hash is fixed so the
  # resulting store path is predictable across runs and stable for
  # the narinfo URL (`/<view>/<storeHash>.narinfo`).
  testPkg = {
    name = "testpkg";
    version = "1.0";
    storeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  };
  # AOS_ROOT-relative store path. The server package exports
  # AOS_ROOT=/var/lib/aos-registry-server/store-root, so the
  # fabricated package lives at $AOS_ROOT/store/<hash>-name-version.
  # The client materialises the same string after `apm install` —
  # the test stub has no internal store-path references, so the
  # prefix is just a hash-locked label.
  serverStoreRoot = "/var/lib/aos-registry-server/store-root";
  storePath = "${serverStoreRoot}/store/${testPkg.storeHash}-${testPkg.name}-${testPkg.version}";

  # `registry.toml` is fully static — built once at eval time. The
  # `[[caches]]` entry resolves `server` via the fleet's /etc/hosts
  # → 192.168.50.11. `lib.formats.toml.generate` returns a
  # derivation; the testScript reads `${registryToml}/registry.toml`
  # as a normal store path on the build host.
  registryToml = tomlFmt.generate "registry.toml" {
    registry = {
      name = "test-reg";
      description = "Fleet test registry";
    };
    # The committed cache topology uses the unified stack schema. A single
    # endpoint is the minimal production form of the `[caches]` table.
    caches.endpoint = "http://server:15000/default";
  };

  # Package TOML skeleton with the `__NAR_HASH__` marker; the runtime
  # `sed` substitutes the real NAR hash read back from the cache's
  # narinfo. The schema dropped `download_hash`/`download_size` after
  # apm switched to reading those from narinfo (FileHash / FileSize).
  packageTomlSkeleton = tomlFmt.generate "testpkg.toml" {
    package = {
      name = testPkg.name;
      description = "Fleet test package";
      license = "MIT";
      maintainer = "test";
    };
    versions = [
      {
        version = testPkg.version;
        platforms.x86_64-linux = {
          store_path = storePath;
          nar_hash = "__NAR_HASH__";
          nar_size = 0;
          closure_size = 0;
          source_drv = "";
          source_nar_hash = "";
          references = [];
        };
      }
    ];
  };
in {
  name = "apm-e2e";
  # 600s budget: two VM boots + package activation + server-side seeding
  # (git init, NAR push, narinfo readback, commit/push) + client sync
  # + install. The original 240s was tight even before the FileHash
  # narinfo computation got wired in (server compresses the path
  # once per narinfo); under sandbox CPU/IO contention this can take
  # tens of seconds.
  timeout = 600;

  machines = {
    # Lexicographic order → client=192.168.50.10, server=192.168.50.11.
    client = {
      system = systems.server-test;
      # No registry package. `apm` ships via modules/base/apm.nix.
    };

    server = {
      system = serverWithRegistry;
      packages = ["aos-registry-server"];
    };
  };

  testScript =
    # python
    ''
      import base64
      import pathlib
      import textwrap

      # ── 1. Server units up; cache reachable from client over L2 ──
      # `wait_for_unit` confirms the unit reached "active" — for our
      # Type=simple cache, that's enough that the bind() has happened.
      # The reachability proof is the client-side curl: it exercises
      # both the multicast L2 between VMs and the cache's responsiveness
      # to GETs from a peer. Git reachability is covered transitively
      # by step 4 (`apm update` does a git fetch). A server-loopback
      # curl was tried and dropped — the nftables ruleset's
      # `iifname "lo" accept` rule appears not to fire for connect()s
      # to 127.0.0.1 on the busybox-curl variant in this image, even
      # though the client-side curl works fine. Diagnosed once;
      # documenting here so it doesn't get rediscovered.
      server.wait_for_unit("aos-registry-server-gitd.service", timeout=60)
      server.wait_for_unit("aos-pkg-aos-registry-server-firewall.service", timeout=60)
      server.wait_for_unit("aos-registry-server-cache.service", timeout=60)
      server.wait_until_succeeds("systemctl is-active aos-pkg-aos-registry-server.target", timeout=60)
      client.wait_until_succeeds(
          "curl -sf --max-time 5 http://server:15000/default/nix-cache-info",
          timeout=60,
      )

      # ── 2. Pre-condition: store path absent on client before install.
      # Load-bearing for step 5 — proves the post-install path didn't
      # come from the image's shared closure. Bumped timeout: the
      # very first agent round-trip to the client races with the
      # tail end of its boot under sandbox CPU contention and the
      # default 30s can run out before the agent dispatches the
      # command.
      client.fail("test -e ${storePath}", timeout=120)

      # ── 3. Server-side seeding ────────────────────────────────────
      # Ship the pre-rendered TOMLs as base64 blobs. base64 round-
      # trips through bash arg parsing without quote escaping; the
      # decode happens guest-side.
      registry_toml_b64 = base64.b64encode(
          pathlib.Path("${registryToml}/registry.toml").read_bytes()
      ).decode()
      package_toml_b64 = base64.b64encode(
          pathlib.Path("${packageTomlSkeleton}/testpkg.toml").read_bytes()
      ).decode()

      # One big bash block — keeps JWT, NAR_HASH, etc. in shell-local
      # scope across the dance. Python f-string, so any literal `{` or
      # `}` inside the embedded shell/JSON must be doubled.
      server.succeed(textwrap.dedent(f"""
          set -euo pipefail
          export AOS_ROOT=${serverStoreRoot}

          # 3.1 Init the bare repo + a working clone. The gitd unit's
          # `StateDirectory=aos-registry-server/registries` (mode 0755)
          # already created the parent; root creates the per-registry
          # subdir below it. Ownership is transferred to aos-gitd at the
          # end of seeding (step 3.10) so git's CVE-2022-24765 guard
          # accepts daemon reads — doing it now would trip the same
          # guard against root's own subsequent clone/push.
          REG_DIR=/var/lib/aos-registry-server/registries/test-reg
          git init --bare --object-format=sha256 "$REG_DIR"
          # No `touch git-daemon-export-ok` — the unit passes
          # --export-all, which makes the marker file unnecessary.
          WORK=$(mktemp -d)
          git clone "$REG_DIR" "$WORK/work-clone"
          cd "$WORK/work-clone"
          git config user.email test@aos
          git config user.name 'AOS test'

          # 3.2 Drop the pre-rendered registry.toml.
          echo '{registry_toml_b64}' | base64 -d > registry.toml

          # 3.3 Fabricate the AOS_ROOT-rooted store path. The package's
          # StateDirectory= already created $AOS_ROOT (mode 0755,
          # owned by aos-gitd since the cache service runs under a
          # stable non-root user).
          mkdir -p ${storePath}/bin
          printf '%s\\n%s\\n' '#!/bin/sh' 'echo "${testPkg.name} ${testPkg.version}"' \\
              > ${storePath}/bin/${testPkg.name}
          chmod +x ${storePath}/bin/${testPkg.name}

          # 3.4 Register in ValidPaths so `aos cache push` finds it.
          # Schema matches tests/vm/apm/cache.nix:36.
          #
          # The `hash` column has to be the *real* NAR hash of the
          # on-disk content. `aos cache push`'s pack path shells out
          # to `nix-store --export ${storePath}` (via
          # `streaming_export` in aos-cache/src/compress.rs), and Nix
          # refuses with `"hash of path ... has changed from ... to
          # ..."` if the registered hash doesn't match what it just
          # computed by re-NARing the path. So precompute the hash
          # here. `nix-store --dump` is also used in the bigpkg
          # tripwire at step 3.9, but that path goes through
          # `streaming_compress` (also `--dump`) which doesn't
          # hash-check against ValidPaths — placeholder hash is fine
          # there.
          mkdir -p "$AOS_ROOT/var/nix/db"
          if [ ! -e "$AOS_ROOT/var/nix/db/db.sqlite" ]; then
            sqlite3 "$AOS_ROOT/var/nix/db/db.sqlite" <<'SQL'
              CREATE TABLE IF NOT EXISTS ValidPaths (
                id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                path TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
                registrationTime INTEGER NOT NULL,
                deriver TEXT, narSize INTEGER, ultimate INTEGER,
                sigs TEXT, ca TEXT
              );
              CREATE TABLE IF NOT EXISTS Refs (
                referrer INTEGER NOT NULL, reference INTEGER NOT NULL,
                PRIMARY KEY (referrer, reference)
              );
              PRAGMA journal_mode=WAL;
          SQL
          fi
          NAR_TMP=$(mktemp)
          NIX_STORE_DIR=$AOS_ROOT/store NIX_STATE_DIR=$AOS_ROOT/var/nix \\
            ${pkgs.nix}/bin/nix-store --dump ${storePath} > "$NAR_TMP"
          NAR_HASH=$(sha256sum "$NAR_TMP" | awk '{{print $1}}')
          NAR_SIZE=$(stat -c %s "$NAR_TMP")
          rm -f "$NAR_TMP"
          # Seed the `ca` column so the server's `validate_imported_path`
          # check (aos-server/src/pack.rs:140-189) treats this path as a
          # fixed-output content-addressed path and accepts it. The pack-
          # import handler refuses to register anything that's not .drv
          # or CA, on the grounds that unverified non-CA store paths from
          # remote uploaders could smuggle in arbitrary binaries. The
          # `fixed:r:sha256:<NAR_HASH>` form is what Nix writes for
          # `--add-fixed --recursive sha256 …`: same shape, with the
          # NAR-hash we just computed. Nix's path-info reads the column
          # verbatim and doesn't recompute store-path hashing against it,
          # so the placeholder store-prefix (`aaaa…`) is fine to keep.
          sqlite3 "$AOS_ROOT/var/nix/db/db.sqlite" \\
            "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs, ca) VALUES ('${storePath}', 'sha256:$NAR_HASH', 1000000, $NAR_SIZE, 1, ''', 'fixed:r:sha256:$NAR_HASH');"

          # 3.4b Promote the path into the view's `bin/` namespace.
          # `aos cache push` ends up creating a GC root under
          # `gcroots/{{view}}/tmp/{{hash}}` (see
          # `upload_pack_handler` → `create_tmp_root`), but the
          # narinfo / NAR handlers go through `check_visibility`
          # which only consults `bin/` and `src/`
          # (aos-server/src/views.rs:48-58). In production a `bin/`
          # root is materialised once `apm build` completes; the
          # fleet test isn't running a build, so we materialise it
          # by hand. Without this, step 3.6's narinfo curl would 404
          # even though the path is valid in the Nix store.
          mkdir -p "$AOS_ROOT/gcroots/default/bin"
          ln -sfn ${storePath} "$AOS_ROOT/gcroots/default/bin/${testPkg.storeHash}"

          # 3.5 Mint provisioning token via the bootstrap socket.
          # Wait for the socket to actually appear — the unit is
          # "active" before its first accept(), so a hard race is
          # possible on a cold VM. `aos cache push --token "$PROV"`
          # performs the PROV → JWT exchange internally via the
          # `oauth2/token` endpoint, so we don't need to do it here.
          for _ in 1 2 3 4 5 6 7 8 9 10; do
            test -S /run/aos-registry-server/bootstrap.sock && break
            sleep 0.5
          done
          RESP=$(echo '{{"action":"create","views":["default"],"permissions":["read","build","gc"]}}' \\
            | socat - UNIX-CONNECT:/run/aos-registry-server/bootstrap.sock)
          PROV=$(echo "$RESP" | jq -r '.data.token')
          [ -n "$PROV" ] && [ "$PROV" != "null" ] || {{ echo "FAIL: no PROV token" >&2; exit 1; }}

          # 3.6 Push the NAR, then read back the real NarHash from the
          # cache's on-demand narinfo. apm now sources FileHash/FileSize
          # from the narinfo at install time, so the only value the
          # package TOML still carries is `nar_hash`. The narinfo route
          # is anonymous-readable because the default view has
          # `anonymous_read = true`.
          ${pkgs.aos}/bin/aos cache push ${storePath} \\
            --to http://127.0.0.1:15000/default --token "$PROV" 2>&1
          chown -R aos-gitd:aos-gitd "$AOS_ROOT/store" "$AOS_ROOT/var/nix"
          NARINFO=$(curl -sf \\
            "http://127.0.0.1:15000/default/${testPkg.storeHash}.narinfo")
          NAR_HASH=$(echo "$NARINFO" | awk '/^NarHash:/ {{print $2}}')
          # NarHash comes out in `sha256:<hex>` form. Sanity check: must
          # be non-empty so the sed substitution below produces a valid
          # TOML.
          test -n "$NAR_HASH" || {{ echo "FAIL: narinfo missing NarHash" >&2; exit 1; }}

          # 3.7 Materialise testpkg.toml from the eval-time skeleton.
          mkdir -p packages/t
          echo '{package_toml_b64}' | base64 -d \\
            | sed -e "s|__NAR_HASH__|$NAR_HASH|" \\
            > packages/t/${testPkg.name}.toml

          # 3.9 Cross-failing tripwire for the deferred put_nar AOS
          # bug. --batch-threshold 0 forces the per-file put_nar path
          # instead of upload_pack. That path is broken on two axes
          # upstream: (1) URL — PUT goes to /{{view}}/nar/<file> but
          # the server's only PUT route is /{{view}}/store/<hash>;
          # (2) body format — the server pipes the body into
          # nix-store --import, which expects raw NAR + ExportTrailer,
          # not compressed NAR. See the TODO block in
          # crates/aos-cache/src/backend/http.rs::put_nar. When someone
          # fixes that path, the `if cmd; then exit 1` below fires in
          # CI and the fixer must delete this block (or flip `if` →
          # `if !`). The check is intentionally exit-code only — a
          # tripwire for "bug is gone", not a tight oracle.
          #
          # The pusher gets its OWN store root: push now dedups via the
          # server's /query-missing before uploading, and the server
          # answers from its nix DB. With the bogus path registered in
          # the shared $AOS_ROOT DB (as this block originally did), the
          # server reports it as already cached and the push exits 0
          # without ever reaching put_nar — firing the tripwire for the
          # wrong reason. A separate pusher root keeps the path missing
          # on the server so the broken upload path is still exercised.
          PUSHER_ROOT=/tmp/tripwire-root
          mkdir -p "$PUSHER_ROOT/store" "$PUSHER_ROOT/var/nix/db"
          cp "$AOS_ROOT/var/nix/db/db.sqlite" "$PUSHER_ROOT/var/nix/db/db.sqlite"
          BIG=$PUSHER_ROOT/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bigpkg-1.0
          mkdir -p "$BIG/share"
          dd if=/dev/urandom of="$BIG/share/blob" bs=1M count=2 status=none
          sqlite3 "$PUSHER_ROOT/var/nix/db/db.sqlite" \\
            "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('$BIG', 'sha256:0000000000000000000000000000000000000000000000000000000000000002', 2100000, 4096, 1, ''');"
          if AOS_ROOT=$PUSHER_ROOT ${pkgs.aos}/bin/aos cache push "$BIG" \\
              --to http://127.0.0.1:15000/default --token "$PROV" \\
              --batch-threshold 0 2>&1; then
            echo "CROSS-FAIL FIRED: aos cache push --batch-threshold 0 unexpectedly succeeded." >&2
            echo "The deferred put_nar AOS bug appears fixed — delete this block." >&2
            exit 1
          fi
          echo "Cross-failing put_nar assertion held — push still fails as expected."

          # 3.8 Commit + tag + push to the bare repo. The apm
          # registry sync's default tracking mode is "latest tag by
          # version-sort" (`registry/git.rs::resolve_latest_tag`),
          # so we need at least one tag for `apm update` to pick a
          # ref. Existing apm VM tests follow the same convention
          # (`tests/vm/apm/tracking.nix`).
          git add -A
          git commit -m 'publish ${testPkg.name} ${testPkg.version}'
          git tag v1.0.0
          git push origin HEAD --tags

          # 3.10 Hand the bare repo over to the gitd daemon's user. Done
          # last so root's earlier git invocations on the same tree
          # aren't blocked by CVE-2022-24765's dubious-ownership check.
          chown -R aos-gitd:aos-gitd "$REG_DIR"
      """), timeout=240)

      # ── 4. Client adds the registry and syncs ─────────────────────
      # Invoke via the store path, not via /usr/bin/apm — the
      # rootfs symlink farm omits dotfiles, so `.apm-unwrapped`
      # isn't next to the PATH-installed `apm` and the wrapper's
      # `dirname "$0"` resolution fails. Calling the store-path
      # binary directly makes `dirname` resolve to the bin/ that
      # contains both wrapper and `.apm-unwrapped`.
      #
      # `HOME=/tmp` is set explicitly: the AOS rootfs ships `/` as
      # read-only, so the `modules/base/apm.nix` tmpfiles.d entries
      # under `/root/.config/...` silently fail at boot (the parent
      # `/root` itself can't gain new children on a read-only fs).
      # apm's `resolve_home()` already falls back to `/tmp` with a
      # warning when `$HOME` is unset — we make it explicit and
      # consistent across every client invocation so registry state
      # and download caches survive across commands. The aos-test-
      # agent doesn't spawn a login shell, so without this every
      # command would see a fresh empty $HOME.
      # `USER=apmfleet` is likewise explicit so the profile path is
      # stable and can be asserted after install.
      client.succeed(
          "HOME=/tmp USER=apmfleet ${pkgs.aos}/bin/apm registry add --no-verify git://server:9418/test-reg --name test-reg",
          timeout=120,
      )
      # `apm update` walks `git fetch` + `git archive | tar -x` over
      # the fleet's multicast L2, which can comfortably overshoot the
      # 30s default agent timeout under host load (other VMs running,
      # cargo recompiles competing for CPU).
      client.succeed(
          "HOME=/tmp USER=apmfleet ${pkgs.aos}/bin/apm update --registry test-reg",
          timeout=120,
      )
      # `extract_packages` strips the leading `packages/` and lands TOMLs
      # under `cache_path()/<registry>/packages/` —
      # `crates/aos-package/src/{update,registry/git}.rs::extract_packages`.
      # `cache_path()` is `$HOME/.local/share/apm/remote` for the user scope
      # (see `types.rs::cache_path`), not `.../registries` (which holds the
      # bare git clone metadata).
      client.succeed(
          "test -f /tmp/.local/share/apm/remote/test-reg/packages/t/${testPkg.name}.toml"
      )

      # ── 5. Install pulls the NAR from the server's cache ──────────
      # `apm install` fetches narinfo, downloads the NAR over the
      # cross-VM L2, runs nix-store --import. Generous timeout —
      # narinfo fetch path on the server runs `nix-store --dump |
      # zstd | sha256sum` to fill in `FileHash` (compress.rs's
      # `compute_file_hash_size`), and apm-side `nix-store --import`
      # invocations can be slow inside the sandboxed VM.
      #
      # `AOS_ROOT` is set so apm's `nix-store --import` (via
      # `aos_nix_env()`) materialises the package at the same
      # `${serverStoreRoot}/store/...` string the package TOML names —
      # the test fixes that path as a hash-locked label shared with the
      # server. The store + Nix state dirs live on the writable `/var`
      # partition; create them up front so `nix-store --import` has a
      # place to write its DB and the path.
      # mkdir + install in one round-trip — keeps the agent-command count
      # down (each cross-VM round-trip is a flake surface under load).
      client.succeed(
          "mkdir -p ${serverStoreRoot}/store ${serverStoreRoot}/var/nix/db && "
          "AOS_ROOT=${serverStoreRoot} HOME=/tmp USER=apmfleet ${pkgs.aos}/bin/apm install ${testPkg.name} --registry test-reg",
          timeout=240,
      )
      # Path was absent in step 2; its presence here proves the NAR
      # was transferred over the network from the server's cache.
      client.succeed("test -x ${storePath}/bin/${testPkg.name}")
      client.succeed(
          "PROFILE_BIN=/var/lib/profiles/per-user/apmfleet/current/bin/${testPkg.name}; "
          "test -x \"$PROFILE_BIN\" && \"$PROFILE_BIN\" | grep -qx '${testPkg.name} ${testPkg.version}'"
      )

      # ── 6. Server's cache logged at least one NAR fetch ───────────
      # `nar_handler` in crates/aos-server/src/routes.rs:272 logs the
      # event with structured fields (view, hash, compression) and
      # the message "NAR streamed" — *not* the URL path. Asserting on
      # `hash=<testPkg.storeHash>` ties the assertion to exactly the
      # NAR we expect the client to have just pulled.
      journal = server.succeed("journalctl -u aos-registry-server-cache --no-pager")
      assert "NAR streamed" in journal, (
          f"expected nar_handler log line, got: {journal!r}"
      )
      assert "hash=${testPkg.storeHash}" in journal, (
          f"expected log for testpkg's store hash, got: {journal!r}"
      )

      # ── 7. Idempotency: second sync exits clean ───────────────────
      client.succeed(
          "HOME=/tmp USER=apmfleet ${pkgs.aos}/bin/apm update --registry test-reg",
          timeout=120,
      )

      # ── 8. Negative path: registry down ───────────────────────────
      # Stop the git daemon. `apm update` should fail — there's no
      # transport to the registry. The cache stays up (independent
      # unit), which is the point of the split: a registry outage
      # doesn't take the binary cache down with it. Restart afterwards
      # so any future operator inspection sees a working server.
      server.succeed("systemctl stop aos-registry-server-gitd.service")
      client.fail(
          "HOME=/tmp USER=apmfleet ${pkgs.aos}/bin/apm update --registry test-reg",
          timeout=120,
      )
      client.succeed("curl -sf http://server:15000/default/nix-cache-info")
      server.succeed("systemctl start aos-registry-server-gitd.service")
    '';
}
