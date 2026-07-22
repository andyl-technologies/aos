# tests/fleet/apm-registry-upgrade.nix - System upgrade pulled from a registry.
#
# The networked counterpart of apm-system-upgrade.nix: the same live
# `apm upgrade --system` generation switch, but the new generation's closure
# is NOT pre-staged on the target; it travels over the fleet L2 from a
# registry peer, exercising the full producer-to-consumer path:
#
#   1. registry VM publishes the server-2 toplevel as a sysroot package
#      (`apr publish --sysroot`) against its real /nix/store (the closure
#      is pre-staged there via extraClosures and registered by
#      aos-nix-db.service), generates a static cache of the FULL closure
#      (`apr cache generate`) into /var/lib/sysreg-cache (served by the
#      static-cache exposed package on :8000), and pushes the registry repo to the
#      gitd-served bare origin on :9418.
#   2. target VM stages the registry in SYSTEM scope (/etc/apm/
#      registries.d + git clone into /var/lib/apm/registries; `apm
#      update` has no --system flag, same pattern as tests/vm/apm/
#      e2e.nix's e2e-system-lifecycle).
#   3. The upgrade must DOWNLOAD the generation delta (~270 MiB: the
#      initrd differs between gens, plus toplevel/etc-erofs/units);
#      asserted three ways: the toplevel is invalid in the target's
#      store beforehand, apm reports "Downloading", and the registry's
#      http.server journal shows NAR GETs from the target.
#   4. The live switch and daemon reconcile must land exactly as in
#      apm-system-upgrade.nix (same assertion battery), then rollback.
#
# Machines (lexicographic order: registry=192.168.50.10, target=192.168.50.11):
#   registry: aos-registry-server package (gitd :9418, cache :15000)
#             + static-cache package (:8000)
#             + extraClosures = [server2Top] (the producer owns the
#             closure) + a /var big enough for the compressed full-closure
#             static cache (~540 MiB).
#   target:   direct upgrade HTTP fixture (same reconcile surface as
#             apm-system-upgrade.nix so its assertions carry over). No
#             extraClosures; the delta must come off the wire, but a
#             /var big enough for the NAR cache + imported store paths
#             (the /nix overlay upper lives on the var partition).
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  fleetSystem = evaluated: {
    # Re-expose extendModules so the harness can bake per-VM identity.
    inherit (evaluated) config options extendModules;
    build = {
      toplevel = evaluated.config.system.build.toplevel;
      kernel = evaluated.config.system.build.kernel;
      initrd = evaluated.config.system.build.initrd;
      image = evaluated.config.system.build.image;
    };
    checks = evaluated.config.system.build.checks;
  };

  # Both machines boot with a baked /var, so the
  # guest agent rides the /var seed; identity + the seeded package list are
  # baked into /etc. They hand-seed the registry (git) and probe HTTP/firewall
  # (curl/nft).
  # server-test provides the bundled agent + those CLI tools (the production
  # server keeps both out of the slim image). The registry additionally
  # re-bundles its fixtures.
  registrySystem = fleetSystem (mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (_: {bundle = true;});
    }
  ]);

  targetSystem = fleetSystem (mkSystem [
    ../../systems/server-test.nix
    (import ../../systems/_upgrade-http-fixture.nix {
      inherit lib pkgs;
      generation = 1;
    })
  ]);

  server2Top = systems.server-2.config.system.build.toplevel;
in {
  name = "apm-registry-upgrade";
  # Two VM boots + fixture/package activation + full-closure static cache generation
  # (zstd over ~1.6 GB) + ~270 MiB cross-VM NAR transfer + import + live
  # switch + rollback. Generous budget for sandbox CPU/IO contention.
  timeout = 1800;

  machines = {
    registry = {
      system = registrySystem;
      packages = ["aos-registry-server" "test-static-cache-server"];
      extraClosures = [server2Top];
      # `apr cache generate` rewrites the FULL ~1.5 GiB system closure into
      # the registry store under /var/lib AND writes the compressed static
      # cache (~540 MiB) alongside it, so /var needs well over 1.5 GiB free.
      # 1536 MiB (the old baked size) overflowed mid-generation; 3072 MiB
      # matches install-from-image.nix's headroom for the same workload.
      # Identity is baked into /etc and /var into the per-machine
      # disk at this size (baking identity already forks the image per machine,
      # so a shared var-less base buys nothing here).
      varSizeMiB = 3072;
      varProvisioning = "baked";
    };

    target = {
      system = targetSystem;
      # The download lands twice on /var: the NAR cache under
      # /var/lib/apm/cache (~270 MiB compressed for the gen-2 delta)
      # AND the imported store paths (the /nix overlay upper lives on
      # the var partition). Sized to match the registry for headroom.
      varSizeMiB = 3072;
      varProvisioning = "baked";
    };
  };

  testScript =
    # python
    ''
      import json
      import textwrap

      # -- 1. Both machines up; registry packages active -----------------
      registry.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      target.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=120)
      registry.wait_for_unit("aos-pkg-aos-registry-server-firewall.service", timeout=120)
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-aos-registry-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-test-static-cache-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active test-static-cache-server.socket", timeout=120
      )
      target.wait_until_succeeds(
          "systemctl is-active test-http-server.service", timeout=120
      )

      # -- 2. Target preconditions: gen-1, closure absent, baselines -----
      target.succeed("test -L /var/lib/profiles/system/current")
      gen_before = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_before == "gen-1", f"expected gen-1, got {gen_before!r}"

      # The Nix DB must be seeded before a check-validity failure is
      # meaningful (an absent DB also fails the check).
      target.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      # The miss is intentional; keep nix-store's expected error off the
      # serial console so unexpected warnings remain visible.
      target.fail(
          "${pkgs.nix}/bin/nix-store --check-validity '${server2Top}' "
          "> /tmp/server2-validity-precheck.out 2>&1"
      )

      # gen-2-only surfaces absent; gen-1 baselines (same as
      # apm-system-upgrade.nix).
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      target.wait_until_succeeds(
          "systemctl is-active aos-upgrade-removed.service", timeout=120
      )
      target.fail("test -e /run/removed-stop-ran")
      baseline_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert baseline_keepalive == "7200", (
          f"unexpected baseline keepalive {baseline_keepalive!r}"
      )
      nftd_before = target.succeed(
          "cat /etc/nftables.conf"
      )
      assert "8443" not in nftd_before, "gen-1 should not yet open port 8443"
      sysctld_before = target.succeed("cat /etc/sysctl.d/10-aos-kernel.conf")
      assert "tcp_keepalive_time" not in sysctld_before, sysctld_before

      # test-http-server's unit is byte-identical across gens; the
      # reconciler must leave it untouched. Asserted after the upgrade.
      http_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())

      # -- 3. Producer: publish the gen-2 closure to the registry --------
      # One bash block: registry create, sysroot
      # publish against the real /nix/store, full-closure static cache into
      # /var/lib/sysreg-cache (served on :8000), commit+tag+push to the gitd origin.
      # `apr publish` shells out to `nix path-info` (a nix-command CLI), so
      # a writable conf dir enables the feature, same as tests/vm/apm's
      # setupNixEnv. Generous timeout: the cache step zstd-compresses the
      # ~1.6 GB closure.
      registry.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      registry.succeed(textwrap.dedent("""
          set -eu
          export HOME=/tmp
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
            > "$NIX_CONF_DIR/nix.conf"

          ${pkgs.nix}/bin/nix-store --check-validity '${server2Top}'

          ${pkgs.aos}/bin/apr create sysreg
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"

          ${pkgs.aos}/bin/apr publish '${server2Top}' \\
            --name aos \\
            --version test-2 \\
            --description 'registry upgrade fixture' \\
            --license MIT \\
            --maintainer test \\
            --sysroot \\
            --no-ca \\
            --registry sysreg \\
            --no-commit
          ${pkgs.aos}/bin/apr verify --registry sysreg

          ${pkgs.aos}/bin/apr cache generate \\
            --registry sysreg \\
            --output /var/lib/sysreg-cache \\
            --cache-url http://registry:8000/sysreg-cache \\
            --priority 46 \\
            --no-commit
          chmod -R a+rX /var/lib/sysreg-cache

          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" commit -m 'release: aos test-2'
          git -C "$REG_DIR" tag v1.0.0
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          chown -R aos-gitd:aos-gitd "$ORIGIN"
      """), timeout=1200)

      # Cache reachable from the target over the fleet L2.
      registry.wait_until_succeeds(
          "curl -sf --max-time 5 http://127.0.0.1:8000/sysreg-cache/nix-cache-info",
          timeout=60,
      )
      target.wait_until_succeeds(
          "curl -sf --max-time 5 http://registry:8000/sysreg-cache/nix-cache-info",
          timeout=60,
      )

      # -- 4. Consumer: stage the registry in SYSTEM scope ---------------
      # `apm upgrade --system` reads /etc/apm/registries.d (config) +
      # /var/lib/apm/remote (synced packages); `apm update` has no
      # --system flag, so sync = git clone + symlink (the documented
      # system-scope pattern, tests/vm/apm/e2e.nix e2e-system-lifecycle).
      target.succeed(textwrap.dedent("""
          set -eu
          mkdir -p /etc/apm/registries.d /var/lib/apm/registries \\
            /var/lib/apm/remote /var/lib/apm/cache
          cat > /etc/apm/registries.d/sysreg.toml <<'EOF'
          [registry]
          name = "sysreg"
          url = "git://registry:9418/sysreg"
          priority = 500
          enabled = true

          [registry.signing]
          required = false
          EOF
          ${pkgs.git}/bin/git clone git://registry:9418/sysreg /var/lib/apm/registries/sysreg
          ln -sfn /var/lib/apm/registries/sysreg /var/lib/apm/remote/sysreg
      """), timeout=120)

      # -- 5. Dry-run surfaces the upgrade -------------------------------
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --dry-run 2>&1",
          timeout=120,
      )
      assert "test-2" in out, f"dry-run did not surface the test-2 target: {out!r}"
      assert "0.1.0" in out, f"dry-run did not name the current 0.1.0 gen: {out!r}"

      # -- 6. The upgrade: NARs come off the wire, then the live switch ---
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=900,
      )
      print("=== apm upgrade --system output ===\n" + out)
      assert "Downloading" in out, (
          f"upgrade did not download anything - closure leaked onto the "
          f"target some other way: {out!r}"
      )

      # The registry's http.server logged NAR GETs from the target;
      # network-transfer proof on the serving side.
      journal = registry.succeed("journalctl -u test-static-cache-server --no-pager")
      assert "GET /sysreg-cache/nar/" in journal, (
          "no NAR fetch logged by the registry's static cache server"
      )

      # -- 7. Generation bookkeeping + closure validity ------------------
      gen_after = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_after == "gen-2", f"expected gen-2, got {gen_after!r}"
      state = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      assert state["current"] == 2, state
      assert len(state["generations"]) == 2, state
      target.succeed("${pkgs.nix}/bin/nix-store --check-validity '${server2Top}'")

      # -- 8. Live /etc reflects gen-2 (overlay swap succeeded) ----------
      target.succeed("test -f /etc/aos/upgrade-test/marker.conf")
      marker = target.succeed("cat /etc/aos/upgrade-test/marker.conf").strip()
      assert marker == "marker = 1", f"unexpected marker content: {marker!r}"
      osrel = target.succeed("cat /etc/os-release")
      assert "VERSION_ID=test-2" in osrel, osrel

      # -- 9. Base /etc policy regenerated; reconciliation applied it ---
      nftd = target.succeed("cat /etc/nftables.conf")
      assert "8443" in nftd, "new nftables ruleset missing port 8443"
      sysctld = target.succeed(
          "cat /etc/sysctl.d/10-aos-kernel.conf"
      )
      assert "tcp_keepalive_time = 300" in sysctld, sysctld
      post_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert post_keepalive == "300", (
          f"sysctl was not re-applied; keepalive is {post_keepalive!r}"
      )
      nft_dump = target.succeed("nft list set inet filter allowed_tcp")
      assert "8443" in nft_dump, nft_dump

      # -- 10. Unit set reconciled: added/removed/unchanged --------------
      target.succeed("systemctl is-active aos-upgrade-test-marker.service")
      target.fail("systemctl is-active aos-upgrade-removed.service")
      target.fail("test -e /etc/systemd/system/aos-upgrade-removed.service")
      target.succeed("test -f /run/removed-stop-ran")
      http_pid_after = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())
      assert http_pid_before == http_pid_after, (
          "test-http-server.service was restarted unnecessarily: PID "
          f"{http_pid_before} -> {http_pid_after}"
      )
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after upgrade: {failed!r}"

      # -- 11. Rollback reverses the live switch -------------------------
      target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm rollback --system --yes 2>&1",
          timeout=300,
      )
      gen_rolled = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_rolled == "gen-1", f"expected gen-1 after rollback, got {gen_rolled!r}"
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")
      osrel_back = target.succeed("cat /etc/os-release")
      assert "VERSION_ID=test-2" not in osrel_back, osrel_back
      assert target.succeed("readlink /run/etc/system").strip() == "system-1"
      target.fail("test -d /run/etc/system-2")
    '';
}
