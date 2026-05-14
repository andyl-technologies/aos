# tests/fleet/apm-e2e.nix — End-to-end fleet test for apm + registry + cache.
#
# Two machines:
#   server (192.168.50.11): aos-registry-server role — git daemon on :9418,
#                            aos serve on :15000. Bootstrap socket on
#                            /run/aos-registry-server/bootstrap.sock.
#   client (192.168.50.10): roleless — relies on modules/base/apm.nix
#                            for `apm` and friends.
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
  pkgs,
  systems,
}: let
  tomlFmt = lib.formats.toml {inherit lib pkgs;};

  # Stable test values. The 32-char store hash is fixed so the
  # resulting store path is predictable across runs and stable for
  # the narinfo URL (`/<view>/<storeHash>.narinfo`).
  testPkg = {
    name = "testpkg";
    version = "1.0";
    storeHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  };
  # AOS_ROOT-relative store path. The server's role exports
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
    caches = [
      {
        url = "http://server:15000/default";
        priority = 100;
      }
    ];
  };

  # Package TOML skeleton with `__NAR_HASH__` / `__DOWNLOAD_HASH__`
  # markers; the runtime `sed` substitutes the real hashes read back
  # from the cache's narinfo. Going through `lib.formats.toml`
  # (instead of templating raw text) keeps the schema typed: missing
  # or mistyped fields fail at eval time. Field shape mirrors
  # tests/vm/apm/fixtures.nix:163 (`write_package_toml`).
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
          download_hash = "__DOWNLOAD_HASH__";
          download_size = 0;
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
  # 240s budget: two VM boots + role activation + server-side seeding
  # (git init, NAR push, narinfo readback, commit/push) + client sync
  # + install. Existing fleet tests under similar load use 180-300.
  timeout = 240;

  machines = {
    # Lexicographic order → client=192.168.50.10, server=192.168.50.11.
    client = {
      system = systems.server;
      # No role. `apm` ships via modules/base/apm.nix.
    };

    server = {
      system = systems.server;
      roles = ["aos-registry-server"];
    };
  };

  testScript = ''
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
    server.wait_for_unit("aos-registry-server-cache.service", timeout=60)
    client.wait_until_succeeds(
        "curl -sf --max-time 5 http://server:15000/default/nix-cache-info",
        timeout=60,
    )

    # ── 2. Pre-condition: store path absent on client before install.
    # Load-bearing for step 5 — proves the post-install path didn't
    # come from the image's shared closure.
    client.fail("test -e ${storePath}")

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
        # `StateDirectory=aos-registry-server/registries` (StateDirectoryMode=0755)
        # already created the parent; root creates the per-registry
        # subdir below it.
        REG_DIR=/var/lib/aos-registry-server/registries/test-reg
        git init --bare "$REG_DIR"
        # No `touch git-daemon-export-ok` — the unit passes
        # --export-all, which makes the marker file unnecessary.
        WORK=$(mktemp -d)
        git clone "$REG_DIR" "$WORK/work-clone"
        cd "$WORK/work-clone"
        git config user.email test@aos
        git config user.name 'AOS test'

        # 3.2 Drop the pre-rendered registry.toml.
        echo '{registry_toml_b64}' | base64 -d > registry.toml

        # 3.3 Fabricate the AOS_ROOT-rooted store path. The role's
        # StateDirectory= already created $AOS_ROOT (mode 0755,
        # owned by root since DynamicUser is off).
        mkdir -p ${storePath}/bin
        printf '%s\\n%s\\n' '#!/bin/sh' 'echo "${testPkg.name} ${testPkg.version}"' \\
            > ${storePath}/bin/${testPkg.name}
        chmod +x ${storePath}/bin/${testPkg.name}

        # 3.4 Register in ValidPaths so `aos cache push` finds it.
        # Schema matches tests/vm/apm/cache.nix:36. Hash placeholder
        # is the same long-form bogus value the existing apm VM
        # tests use; the real hashes come back via narinfo in 3.6.
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
        sqlite3 "$AOS_ROOT/var/nix/db/db.sqlite" \\
          "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs) VALUES ('${storePath}', 'sha256:0000000000000000000000000000000000000000000000000000000000000001', 1000000, 4096, 1, ''');"

        # 3.5 Bootstrap-token → JWT (mirrors tests/vm/apm/e2e.nix:72).
        # Wait for the bootstrap socket to actually appear — the
        # unit is "active" before its first accept(), so a hard race
        # is possible on a cold VM.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
          test -S /run/aos-registry-server/bootstrap.sock && break
          sleep 0.5
        done
        RESP=$(echo '{{"action":"create","views":["default"],"permissions":["read","build","gc"]}}' \\
          | socat - UNIX-CONNECT:/run/aos-registry-server/bootstrap.sock)
        PROV=$(echo "$RESP" | jq -r '.data.token')
        JWT=$(curl -s -X POST \\
          -H "Authorization: Bearer $PROV" \\
          -H "Content-Type: application/x-www-form-urlencoded" \\
          -d "grant_type=client_credentials" \\
          http://127.0.0.1:15000/oauth2/token | jq -r '.access_token')
        [ -n "$JWT" ] && [ "$JWT" != "null" ] || {{ echo "FAIL: no JWT" >&2; exit 1; }}

        # 3.6 Push the NAR, then read back the real hashes from the
        # cache's on-demand narinfo. `apm install` verifies both
        # nar_hash (uncompressed) and download_hash (compressed
        # .nar.zst) — placeholders would fail with HashMismatch
        # (verify.rs:54-94). The narinfo route is anonymous-readable
        # because the default view has `anonymous_read = true`.
        # Tolerate non-zero exit from `aos cache push`: existing apm
        # VM tests do the same (e2e.nix:139) because mock ValidPaths
        # entries can warn at verify time even though the NAR
        # uploads successfully. The narinfo readback below is the
        # real success check.
        ${pkgs.aos}/bin/aos cache push ${storePath} \\
          --to http://127.0.0.1:15000/default --token "$JWT" \\
          2>&1 || echo "WARN: aos cache push returned non-zero (mock ValidPaths hash)"
        NARINFO=$(curl -sf \\
          "http://127.0.0.1:15000/default/${testPkg.storeHash}.narinfo")
        NAR_HASH=$(echo "$NARINFO" | awk '/^NarHash:/ {{print $2}}')
        DL_HASH=$(echo "$NARINFO"  | awk '/^FileHash:/ {{print $2}}')
        # NarHash / FileHash come out in `sha256:<hex>` form, which
        # is exactly what verify.rs compares against. Sanity check:
        # both must be non-empty.
        test -n "$NAR_HASH" || {{ echo "FAIL: narinfo missing NarHash" >&2; exit 1; }}
        test -n "$DL_HASH"  || {{ echo "FAIL: narinfo missing FileHash" >&2; exit 1; }}

        # 3.7 Materialise testpkg.toml from the eval-time skeleton.
        mkdir -p packages/t
        echo '{package_toml_b64}' | base64 -d \\
          | sed -e "s|__NAR_HASH__|$NAR_HASH|" \\
                -e "s|__DOWNLOAD_HASH__|$DL_HASH|" \\
          > packages/t/${testPkg.name}.toml

        # 3.8 Commit + push to the bare repo.
        git add -A
        git commit -m 'publish ${testPkg.name} ${testPkg.version}'
        git push origin HEAD
    """))

    # ── 4. Client adds the registry and syncs ─────────────────────
    # Invoke via the store path, not via /usr/bin/apm — the
    # rootfs symlink farm omits dotfiles, so `.apm-unwrapped`
    # isn't next to the PATH-installed `apm` and the wrapper's
    # `dirname "$0"` resolution fails. Calling the store-path
    # binary directly makes `dirname` resolve to the bin/ that
    # contains both wrapper and `.apm-unwrapped`.
    client.succeed(
        "${pkgs.aos}/bin/apm registry add git://server:9418/test-reg --name test-reg"
    )
    client.succeed("${pkgs.aos}/bin/apm update --registry test-reg")
    client.succeed(
        "test -f /root/.local/share/apm/registries/test-reg/packages/t/${testPkg.name}.toml"
    )

    # ── 5. Install pulls the NAR from the server's cache ──────────
    client.succeed("${pkgs.aos}/bin/apm install ${testPkg.name} --registry test-reg")
    # Path was absent in step 2; its presence here proves the NAR
    # was transferred over the network from the server's cache.
    client.succeed("test -x ${storePath}/bin/${testPkg.name}")

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
    client.succeed("${pkgs.aos}/bin/apm update --registry test-reg")

    # ── 8. Negative path: registry down ───────────────────────────
    # Stop the git daemon. `apm update` should fail — there's no
    # transport to the registry. The cache stays up (independent
    # unit), which is the point of the split: a registry outage
    # doesn't take the binary cache down with it. Restart afterwards
    # so any future operator inspection sees a working server.
    server.succeed("systemctl stop aos-registry-server-gitd.service")
    client.fail("${pkgs.aos}/bin/apm update --registry test-reg")
    client.succeed("curl -sf http://server:15000/default/nix-cache-info")
    server.succeed("systemctl start aos-registry-server-gitd.service")
  '';
}
