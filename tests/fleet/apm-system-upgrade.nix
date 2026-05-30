# tests/fleet/apm-system-upgrade.nix — Live, in-place `apm upgrade --system`.
#
# This is the end-to-end proof for the apm system-upgrade refactor (v2):
# `apm upgrade --system` must reconfigure the *running* system without a
# reboot — swap the /etc overlay to the new generation (P1's activate
# script) AND reconcile the running daemons against the new unit set
# (P4's `apm activate-reconcile`, driven by P2's diff engine over P3's
# X-* unit contract). The fleet harness boots the real `systems.server`
# image with full systemd + dbus, which is what the reconciler needs.
#
# Two machines:
#   registry (192.168.50.10): aos-registry-server role — git daemon on
#                             :9418 serving the test registry, plus the
#                             binary cache on :15000.
#   target   (192.168.50.11): test-http-server role (bundled on
#                             systems.server). Boots on gen-1 =
#                             systems.server. The server-2 toplevel
#                             (gen-2 = systems/server-2.nix) is pre-staged
#                             on its disk via `extraClosures`.
#
# Generation pairing:
#   gen-1 = systems.server         (seeded into state.json at first boot by
#                                   aos-seed-profiles.service: package "aos",
#                                   version "0.1.0", registry "seed").
#   gen-2 = systems/server-2.nix   (imports server.nix; bumps the version,
#                                   adds an environment.etc marker, and gives
#                                   the test-http-server role a new port, a
#                                   sysctl, and a new oneshot unit).
# The test-http-server role is bundled on BOTH gens (the server profile
# bundles it), so the harness's `roles = ["test-http-server"]` merge
# resolves at first boot; the upgrade then introduces the role's deltas
# as a *live* update — exactly the reconciliation surface under test.
#
# ── How the upgrade avoids the network (deviation from spec §8.3) ──────
# The spec's §8.3 sketched a full cache-push dance (nix-store --dump,
# ValidPaths insert, `aos cache push`, narinfo readback, sed). That is
# unnecessary here and is deliberately omitted: §8.2's `extraClosures`
# already pre-stages the entire server-2 closure onto the target's disk,
# so `apm upgrade --system` finds every store path present and downloads
# nothing. The one missing piece the spec didn't call out is that the
# booted AOS system has /nix/store but no Nix *database* (confirmed by
# tests/vm/apm/system.nix's `mkSystemPreamble`), so `nix-store
# --check-validity` — which `apm`'s `filter_missing` uses — would report
# the pre-staged path as missing and try to fetch it. We therefore
# register the server-2 toplevel as valid in the target's Nix DB (the
# `nix-store --init` + `--register-validity` incantation proven in
# system.nix) before the upgrade. With references=[] in the registry
# entry, apm only ever checks the toplevel path itself, so registering
# just that one path is enough. The registry then only needs to serve
# the package TOML over git for `apm update` to discover the test-2
# entry — the cache is up (the role runs it) but never queried.
#
# File bodies (the TOMLs) are shipped as base64 and decoded on the
# guest, dodging shell-quoting hazards — same trick as apm-e2e.nix.
# `${pkgs...}` / `${...Top}` are Nix interpolations resolved at eval time.
{
  lib,
  pkgs,
  systems,
}: let
  tomlFmt = lib.formats.toml {inherit lib pkgs;};

  # gen-2's toplevel. `systems.server-2` is the discovered key for
  # systems/server-2.nix (the fleet discoverer passes `systems` in —
  # see default.nix). Pre-staged on the target via `extraClosures`
  # below; the registry entry's `store_path` names this exact path.
  server2Top = systems.server-2.config.system.build.toplevel;

  # registry.toml — fully static. The `[[caches]]` entry resolves
  # `registry` via the fleet's /etc/hosts → 192.168.50.10. The cache is
  # never queried in this test (the upgrade downloads nothing), but
  # pointing it at the live registry cache keeps the registry config
  # well-formed and reachable for any future download path.
  registryToml = tomlFmt.generate "registry.toml" {
    registry = {
      name = "test-reg";
      description = "apm --system upgrade fleet test registry";
    };
    caches = [
      {
        url = "http://registry:15000/default";
        priority = 100;
      }
    ];
  };

  # Package TOML for the sysroot package "aos" at version "test-2",
  # pointing at the pre-staged server-2 toplevel. Mirrors
  # apm-e2e.nix's packageTomlSkeleton, parametrised over a real system
  # toplevel rather than a fabricated package, and with `sysroot = true`
  # (upgrade_system only considers entries with that flag).
  #
  #   - name MUST equal systems.server's `aos.system.name` (default
  #     "aos") — `upgrade_system` looks up
  #     `reg.packages.get(&current_gen.package_name)`, and gen-1's
  #     package_name is "aos".
  #   - version "test-2" matches systems/server-2.nix's aos.system.version.
  #   - references = [] — the closure is pre-staged on disk and registered
  #     valid, so apm never recurses into references and never downloads.
  #   - nar_hash is a placeholder: with nothing to download there is no
  #     verify step, so the value is never inspected.
  serverPkgToml = tomlFmt.generate "aos.toml" {
    package = {
      name = "aos";
      description = "Upgrade test fixture (server-2 toplevel)";
      license = "MIT";
      maintainer = "test";
      sysroot = true;
    };
    versions = [
      {
        version = "test-2";
        platforms.x86_64-linux = {
          store_path = "${server2Top}";
          nar_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
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
  name = "apm-system-upgrade";
  # Two VM boots + role activation + registry git seeding + a live
  # generation switch (overlay swap + daemon reconcile) + rollback.
  # Generous budget for sandbox CPU/IO contention — matches apm-e2e.nix.
  timeout = 600;

  machines = {
    # Lexicographic order → registry=192.168.50.10, target=192.168.50.11.
    registry = {
      system = systems.server;
      roles = ["aos-registry-server"];
    };

    target = {
      system = systems.server;
      roles = ["test-http-server"];
      # Pre-stage gen-2's full closure so `apm upgrade --system` fetches
      # nothing over the network (see the header note).
      extraClosures = [server2Top];
    };
  };

  testScript =
    # python
    ''
      import base64
      import json
      import pathlib
      import textwrap

      # ── 1. Both machines healthy; cache reachable over the L2 ────────
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=60)
      registry.wait_for_unit("aos-registry-server-cache.service", timeout=60)
      target.wait_until_succeeds(
          "curl -sf --max-time 5 http://registry:15000/default/nix-cache-info",
          timeout=60,
      )

      # ── 2. Target is on gen-1 with the test role already activated ───
      target.succeed("test -L /var/lib/profiles/system/current")
      gen_before = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_before == "gen-1", f"expected gen-1, got {gen_before!r}"

      target.succeed("systemctl is-active test-http-server.service")

      # Role drop-in baseline. gen-1's test-http-server role sets
      # firewall.allowedTCP = [8000] (so the nftables drop-in exists) but
      # no kernel.sysctl (so the sysctl drop-in does NOT exist yet — the
      # drop-ins are emitted only when the corresponding role option is
      # non-empty, modules/roles/default.nix:108,124).
      target.succeed("test -f /etc/nftables.d/50-role-test-http-server.nft")
      target.fail("test -f /etc/sysctl.d/70-role-test-http-server.conf")
      nftd_before = target.succeed(
          "cat /etc/nftables.d/50-role-test-http-server.nft"
      )
      assert "8443" not in nftd_before, "gen-1 should not yet open port 8443"

      # gen-2-only surfaces are absent on gen-1.
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")

      # gen-1 has no tcp_keepalive_time drop-in → the kernel default (7200).
      baseline_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert baseline_keepalive == "7200", (
          f"unexpected baseline keepalive {baseline_keepalive!r}"
      )

      # Record test-http-server's MainPID — its unit file is byte-identical
      # across gen-1 and gen-2 (server-2 only *adds* a unit), so the
      # reconciler must leave it untouched. Asserted after the upgrade.
      http_pid_before = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())

      # ── 3. Registry-side git seeding ────────────────────────────────
      # Ship the pre-rendered TOMLs as base64 blobs. This is the git
      # subset of apm-e2e.nix's seeding — no cache push / NAR / ValidPaths
      # dance, because the upgrade downloads nothing (see header note).
      registry_toml_b64 = base64.b64encode(
          pathlib.Path("${registryToml}/registry.toml").read_bytes()
      ).decode()
      package_toml_b64 = base64.b64encode(
          pathlib.Path("${serverPkgToml}/aos.toml").read_bytes()
      ).decode()

      registry.succeed(textwrap.dedent(f"""
          set -euo pipefail

          # Init the bare repo + a working clone. The gitd unit's
          # StateDirectory= already created the parent registries dir;
          # root creates the per-registry subdir. Ownership is handed to
          # aos-gitd at the end (git's CVE-2022-24765 guard otherwise
          # blocks root's own clone/push against an aos-gitd-owned tree).
          REG_DIR=/var/lib/aos-registry-server/registries/test-reg
          git init --bare "$REG_DIR"
          WORK=$(mktemp -d)
          git clone "$REG_DIR" "$WORK/work-clone"
          cd "$WORK/work-clone"
          git config user.email test@aos
          git config user.name 'AOS test'

          # Drop the registry.toml and the "aos" package TOML. The
          # package name is "aos" → letter dir "a" (apm's extract_packages
          # mirrors the packages/<first-letter>/<name>.toml layout).
          echo '{registry_toml_b64}' | base64 -d > registry.toml
          mkdir -p packages/a
          echo '{package_toml_b64}' | base64 -d > packages/a/aos.toml

          # Commit + tag + push. apm's registry sync tracks the latest tag
          # by version-sort, so at least one tag is required for `apm
          # update` to pick a ref (same convention as the other apm tests).
          git add -A
          git commit -m 'publish aos test-2 (server-2 toplevel)'
          git tag v1.0.0
          git push origin HEAD --tags

          chown -R aos-gitd:aos-gitd "$REG_DIR"
      """), timeout=180)

      # ── 4. Register the pre-staged toplevel valid in the target's Nix
      #       DB so apm's check-validity sees it present (no download) ───
      # The booted system has /nix/store (extraClosures put the whole
      # server-2 closure there) but no Nix DB; initialise it and register
      # the toplevel path. With references=[] in the TOML, apm only checks
      # this one path. (Incantation proven in tests/vm/apm/system.nix.)
      target.succeed(textwrap.dedent("""
          set -euo pipefail
          export NIX_REMOTE=""
          mkdir -p /nix/var/nix/db /nix/var/nix/gcroots /nix/var/nix/temproots /nix/var/nix/userpool
          ${pkgs.nix}/bin/nix-store --init
          printf '%s\\n\\n0\\n' "${server2Top}" | ${pkgs.nix}/bin/nix-store --register-validity
          ${pkgs.nix}/bin/nix-store --check-validity "${server2Top}"
      """), timeout=120)

      # ── 5. Target adds the registry and syncs ───────────────────────
      # Invoke apm by store path (the rootfs symlink farm omits the
      # `.apm-unwrapped` dotfile, breaking the PATH wrapper's dirname
      # resolution) and pin HOME=/tmp (read-only / can't gain /root
      # children) — same rationale as apm-e2e.nix.
      target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm registry add "
          "git://registry:9418/test-reg --name test-reg",
          timeout=120,
      )
      target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm update --registry test-reg",
          timeout=120,
      )

      # ── 6. Dry-run surfaces the available upgrade ───────────────────
      # upgrade_system prints "Current sysroot: aos 0.1.0 ..." and
      # "Upgrade available: aos 0.1.0 -> test-2"; both version strings are
      # the unambiguous signal the test-2 entry was recognised.
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --dry-run 2>&1",
          timeout=120,
      )
      assert "test-2" in out, f"dry-run did not surface the test-2 target: {out!r}"
      assert "0.1.0" in out, f"dry-run did not name the current 0.1.0 gen: {out!r}"

      # ── 7. The actual upgrade ───────────────────────────────────────
      # --yes for non-interactive; default kernel mode (no kernel change
      # in this gen delta, so the kernel handler is a no-op).
      out = target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=300,
      )
      print("=== apm upgrade --system output ===\n" + out)

      # ── 8. Generation bookkeeping ───────────────────────────────────
      gen_after = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_after == "gen-2", f"expected gen-2, got {gen_after!r}"

      state = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      assert state["current"] == 2, state
      assert len(state["generations"]) == 2, state

      # ── 9. Live /etc reflects gen-2 (overlay swap succeeded) ─────────
      # The marker file is symlink-mode environment.etc → baked into
      # gen-2's EROFS metadata image, and the var-seed never writes under
      # /etc/aos/, so its appearance is a clean proof the EROFS lower was
      # swapped to gen-2.
      #
      # NOTE (deviation from spec §8.4): the spec also asserted
      # `VERSION_ID=test-2` in /etc/os-release. That cannot hold in this
      # harness — lib/testing/vm.nix's var-seed writes /var/etc/os-release
      # (VERSION_ID=0.1), and /var/etc is the highest-precedence lower in
      # the three-layer /etc overlay (modules/services/ignition.nix:309),
      # so it shadows the gen's EROFS os-release on every generation. The
      # marker file (which the var-seed does not write) is the load-bearing
      # EROFS-swap proof instead.
      target.succeed("test -f /etc/aos/upgrade-test/marker.conf")
      marker = target.succeed(
          "cat /etc/aos/upgrade-test/marker.conf"
      ).strip()
      assert marker == "marker = 1", f"unexpected marker content: {marker!r}"

      # ── 10. Role drop-ins regenerated on the per-gen ignition lower ──
      nftd = target.succeed("cat /etc/nftables.d/50-role-test-http-server.nft")
      assert "8443" in nftd, "new nftables drop-in missing port 8443"

      sysctld = target.succeed(
          "cat /etc/sysctl.d/70-role-test-http-server.conf"
      )
      assert "tcp_keepalive_time = 300" in sysctld, sysctld

      # ── 11. Reconciliation acted on the drop-in changes ─────────────
      # systemd-sysctl restarted (no ExecReload → restart) via its
      # X-Reload-Triggers on /etc/sysctl.d, re-applying every sysctl —
      # the kernel's runtime keepalive must now reflect the new drop-in.
      post_keepalive = target.succeed(
          "cat /proc/sys/net/ipv4/tcp_keepalive_time"
      ).strip()
      assert post_keepalive == "300", (
          f"sysctl was not re-applied; keepalive is {post_keepalive!r}"
      )

      # nftables reloaded (it has ExecReload → reload) via its
      # X-Reload-Triggers on /etc/nftables.d — port 8443 is now allowed.
      nft_dump = target.succeed("nft list set inet filter allowed_tcp")
      assert "8443" in nft_dump, nft_dump

      # ── 12. The newly-added unit was installed and started ──────────
      target.succeed("systemctl is-active aos-upgrade-test-marker.service")

      # ── 13. The unchanged unit was NOT restarted (diff stayed precise) ─
      http_pid_after = int(target.succeed(
          "systemctl show -p MainPID --value test-http-server.service"
      ).strip())
      assert http_pid_before == http_pid_after, (
          "test-http-server.service was restarted unnecessarily: PID "
          f"{http_pid_before} -> {http_pid_after}"
      )

      # ── 14. No failed units after the reconcile ─────────────────────
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after upgrade: {failed!r}"

      # ── 15. Rollback reverses the live switch ───────────────────────
      target.succeed(
          "HOME=/tmp ${pkgs.aos}/bin/apm rollback --system --yes 2>&1",
          timeout=300,
      )
      gen_rolled = target.succeed(
          "readlink /var/lib/profiles/system/current"
      ).strip()
      assert gen_rolled == "gen-1", f"expected gen-1 after rollback, got {gen_rolled!r}"

      # The marker file is gone (EROFS swapped back to gen-1).
      target.fail("test -e /etc/aos/upgrade-test/marker.conf")
      # The added unit is torn down with gen-2.
      target.fail("test -e /etc/systemd/system/aos-upgrade-test-marker.service")

      # /run/etc bookkeeping: the active system lower points back at
      # system-1, and Phase C tore down gen-2's mounts.
      assert target.succeed("readlink /run/etc/system").strip() == "system-1"
      target.fail("test -d /run/etc/system-2")
    '';
}
