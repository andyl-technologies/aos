# tests/fleet/apr-release-e2e.nix — End-to-end `apr release` over the fleet.
#
# Exercises the all-or-nothing `apr release` producer pipeline and a real
# consumer install across the fleet's multicast L2:
#
#   registry (192.168.50.11): aos-registry-server (gitd :9418) +
#     test-static-cache-server (:8000, serving /var/lib). The producer
#     fabricates a store path, `apr create`s a signed registry, and runs a
#     SINGLE `apr release` that publishes the package, stages + uploads the
#     static binary cache to a served directory, advertises the `[[caches]]`
#     pointer, and signs the release tag — then pushes the registry git to the
#     gitd origin so the consumer can clone it.
#   client (192.168.50.10): package-less. `apm registry add` over git://, then
#     `apm install` pulls the NAR from the HTTP-served static cache.
#
# Unlike apm-e2e.nix (which drives `aos cache push` + a hand-written package
# TOML), the producer here does everything through `apr release`: the unified
# command writes the package TOML, generates and uploads the cache, and commits
# the cache pointer in one transactional unit. A second release of the same
# closure asserts the remote-skip path: nothing is regenerated.
#
# `testScript` is Python (Machine API). The producer dance runs as one
# `registry.succeed(textwrap.dedent("""..."""))` so shell vars stay in scope.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  # server-test bundles the guest agent and the CLI tools fleet scripts need
  # (the producer hand-seeds + signs the registry with git/sqlite; the client
  # polls the static cache with curl) — image slimming keeps those out of the
  # production server. The registry additionally re-bundles its fixtures; the
  # consumer client just needs the tools (systems.server-test).
  serverWithRegistry = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (_: {bundle = true;});
    }
  ];

  # Fixed 32-char store hash → predictable store path and narinfo basename.
  pkg = {
    name = "relpkg";
    # The package version is encoded in the store-path basename and is what
    # `apr release` records for the package. It is deliberately different from
    # the registry release tags below: the `<SEMVER>` positional names the
    # registry release, never the package version (which apr re-extracts from
    # the store path, exactly as a plain `apr publish` would).
    version = "1.2.3";
    storeHash = "cccccccccccccccccccccccccccccccc";
  };
  # Registry release tags, distinct from `pkg.version`, so the test exercises
  # that the positional `<SEMVER>` sets only the registry tag.
  releaseTag = "1.0.0";
  secondReleaseTag = "2.0.0";
  # The aos-registry-server package exports AOS_ROOT here, so the fabricated path
  # lives at $AOS_ROOT/store/<hash>-name-version and apr reads it via the same
  # AOS_ROOT-aware nix environment.
  serverStoreRoot = "/var/lib/aos-registry-server/store-root";
  storePath = "${serverStoreRoot}/store/${pkg.storeHash}-${pkg.name}-${pkg.version}";
in {
  name = "apr-release-e2e";
  # Two VM boots + package activation + fabrication + `apr release` (publish +
  # static-cache zstd + upload + sign) + a second skip-only release + consumer
  # add/install. Generous budget for sandbox CPU/IO contention.
  timeout = 900;

  machines = {
    # Lexicographic order → client=192.168.50.10, registry=192.168.50.11.
    client = {
      system = systems.server-test;
      # No test package. `apm` ships via modules/base/apm.nix.
    };

    registry = {
      system = serverWithRegistry;
      packages = ["aos-registry-server" "test-static-cache-server"];
      # The static cache and origin land under /var/lib (served on :8000);
      # the default 256 MiB /var is tight once the NAR is compressed in.
      varSizeMiB = 1024;
    };
  };

  testScript =
    # python
    ''
      import textwrap

      # ── 1. Registry packages up; cache reachable from the client over L2 ──
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=120)
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-test-static-cache-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active test-static-cache-server.socket", timeout=120
      )
      registry.succeed("mkdir -p /var/lib/sysreg-cache && chmod a+rX /var/lib/sysreg-cache")
      registry.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      # Probe the served cache dir, not the server root: the static cache
      # server's Landlock grant only covers /var/lib/sysreg-cache, so a GET on
      # `/` (which would list /var/lib) is denied. The dir exists (created
      # above) and is empty until the release, so this lists 200.
      client.wait_until_succeeds(
          "curl -sf --max-time 5 http://registry:8000/sysreg-cache/ -o /dev/null", timeout=120
      )

      # Pre-condition: the package is absent on the client before install.
      client.fail("test -e ${storePath}", timeout=120)

      # ── 2. Producer: one `apr release` publishes + caches + advertises ──
      # Python f-string → literal `{`/`}` in the embedded shell must be doubled.
      release = registry.succeed(textwrap.dedent(f"""
          set -euo pipefail
          exec 2>&1
          export HOME=/tmp AOS_ROOT=${serverStoreRoot}
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\n' \\
            > "$NIX_CONF_DIR/nix.conf"

          # 2.1 Fabricate the store path and register it as a fixed-output
          # (content-addressed) ValidPath so `apr release` can dump its NAR.
          # The `ca` column must carry the real NAR hash or `nix-store --dump`
          # refuses with a hash-mismatch (same constraint as apm-e2e.nix).
          mkdir -p ${storePath}/bin
          printf '%s\\n%s\\n' '#!/bin/sh' 'echo "${pkg.name} ${pkg.version}"' \\
            > ${storePath}/bin/${pkg.name}
          chmod +x ${storePath}/bin/${pkg.name}

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
          sqlite3 "$AOS_ROOT/var/nix/db/db.sqlite" \\
            "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ultimate, sigs, ca) VALUES ('${storePath}', 'sha256:$NAR_HASH', 1000000, $NAR_SIZE, 1, ''', 'fixed:r:sha256:$NAR_HASH');"

          # 2.2 Signed registry + a bare gitd origin the consumer clones from.
          # `apr keys generate` writes the maintainer key and prints its
          # public half; `apr create --trust-key` then initialises the
          # registry (directory + git repo + keys.toml roster seeded with
          # that key) so the release below can be published and signed.
          KEYGEN=$(${pkgs.aos}/bin/apr keys generate release --registry relreg 2>&1)
          printf '%s\\n' "$KEYGEN"
          PUBKEY=$(printf '%s\\n' "$KEYGEN" | awk '/Public key:/ {{print $NF; exit}}')
          test -n "$PUBKEY"
          KEY=$HOME/.config/apm/keys/relreg-release.key
          ${pkgs.aos}/bin/apr create relreg --trust-key "$PUBKEY" --key "$KEY"
          REG_DIR=$HOME/.local/share/apm/registries/relreg
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/relreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"

          # 2.3 The single transactional release: publish + cache + advertise +
          # sign. The static cache is staged internally and uploaded to the
          # served directory; --cache-url is the consumer-facing read URL.
          # apr writes its progress/success lines to stderr (stdout stays
          # reserved for machine data) and the driver's succeed() returns
          # stdout, so fold stderr into stdout (2>&1) for the asserts below.
          ${pkgs.aos}/bin/apr release ${releaseTag} \\
            --registry relreg \\
            --store-path ${storePath} \\
            --name ${pkg.name} \\
            --description 'apr release fleet fixture' \\
            --license MIT \\
            --maintainer test \\
            --key "$KEY" \\
            --cache-url http://registry:8000/sysreg-cache \\
            --upload-url file:///var/lib/sysreg-cache 2>&1
          chmod -R a+rX /var/lib/sysreg-cache

          # 2.4 Push the released registry (package, pointer, tag) to gitd.
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          chown -R aos-gitd:aos-gitd "$ORIGIN"
      """), timeout=600)
      print("=== apr release output ===\n" + release)
      assert "Updated registry.toml [[caches]]" in release, release
      assert "Generated static cache: 1 narinfos, 1 NARs" in release, release
      assert "Released relreg ${releaseTag}" in release, release

      # Decoupling: the registry release is tagged ${releaseTag}, but the
      # package version apr recorded is the store-path version (${pkg.version}),
      # NOT the release tag. The old behavior forced the <SEMVER> positional
      # onto the package, which would have recorded ${releaseTag} here.
      relpkg_toml = registry.succeed(
          "cat /tmp/.local/share/apm/registries/relreg/packages/r/relpkg.toml"
      )
      assert 'version = "${pkg.version}"' in relpkg_toml, relpkg_toml
      assert 'version = "${releaseTag}"' not in relpkg_toml, relpkg_toml

      # The static cache landed at the served directory.
      registry.succeed("test -d /var/lib/sysreg-cache/nar")
      target_url = "http://registry:8000/sysreg-cache/nix-cache-info"
      client.wait_until_succeeds(f"curl -sf --max-time 5 {target_url}", timeout=60)

      # ── 3. Consumer adds the registry and installs from the cache ──────
      client.succeed(
          "HOME=/tmp USER=relfleet ${pkgs.aos}/bin/apm registry add "
          "--no-verify git://registry:9418/relreg --name relreg",
          timeout=120,
      )
      client.succeed(
          "HOME=/tmp USER=relfleet ${pkgs.aos}/bin/apm update --registry relreg",
          timeout=120,
      )
      client.succeed(
          "mkdir -p ${serverStoreRoot}/store ${serverStoreRoot}/var/nix/db && "
          "AOS_ROOT=${serverStoreRoot} HOME=/tmp USER=relfleet "
          "${pkgs.aos}/bin/apm install ${pkg.name} --registry relreg",
          timeout=240,
      )
      # The path was absent in step 1; its presence proves the NAR transferred
      # from the registry's HTTP-served static cache.
      client.succeed("test -x ${storePath}/bin/${pkg.name}")
      client.succeed(
          "PROFILE_BIN=/var/lib/profiles/per-user/relfleet/current/bin/${pkg.name}; "
          "test -x \"$PROFILE_BIN\" && \"$PROFILE_BIN\" | grep -qx '${pkg.name} ${pkg.version}'"
      )

      # The registry's static cache server logged a NAR GET from the client.
      journal = registry.succeed("journalctl -u test-static-cache-server --no-pager")
      assert "GET /sysreg-cache/nar/" in journal, journal

      # ── 4. Skip path: a second registry release over the same closure ──
      # No --store-path, no new package: this just cuts registry release
      # ${secondReleaseTag} over the closure already published as
      # ${pkg.name} ${pkg.version}. The registry tag advances independently of
      # any package version, and because the closure's root narinfo is already
      # on the destination the whole static cache is skipped (§7.4 early-out).
      second = registry.succeed(textwrap.dedent("""
          set -euo pipefail
          exec 2>&1
          export HOME=/tmp AOS_ROOT=${serverStoreRoot}
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_CONF_DIR=/tmp/nix-conf
          KEY=$HOME/.config/apm/keys/relreg-release.key
          ${pkgs.aos}/bin/apr release ${secondReleaseTag} \\
            --registry relreg \\
            --key "$KEY" \\
            --cache-url http://registry:8000/sysreg-cache \\
            --upload-url file:///var/lib/sysreg-cache 2>&1
      """), timeout=300)
      print("=== second apr release output ===\n" + second)
      assert "Released relreg ${secondReleaseTag}" in second, second
      assert "Generated static cache: 0 narinfos, 0 NARs" in second, second
      assert "remote-skipped" in second, second
    '';
}
