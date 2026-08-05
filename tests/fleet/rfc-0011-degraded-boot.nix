# tests/fleet/rfc-0011-degraded-boot.nix — RFC-0011 soft/hard graph edges.
#
# The live machine first evaluates three genuine exposed packages. The test
# then injects one unreachable, authenticated-output-shaped pin at the
# manifest/graph boundary and re-drives the production systemd graph. This is
# intentionally below name resolution: the failure under test is the fetch
# wing, not the evaluator. One independent package must still render and stay
# live, while a fetched package depending on the failed output is cascade
# dropped from the committed, dependency-closed manifest.
#
# A second machine replaces the real initrd mount-var body with a deterministic
# failure. mount-var is a hard substrate dependency of initrd-fs and the /etc
# overlay, so that boot must enter the initrd emergency path and never reach
# stage 2.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  degradedSystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages.desired-config-test = {
        package = pkgs.desired-config-test;
        bundle = true;
        preset = false;
      };
      aos.packages.desired-prune-test = {
        package = pkgs.desired-prune-test;
        bundle = true;
        preset = false;
      };
      aos.packages.test-http-server = {
        package = pkgs.test-http-server;
        bundle = true;
        preset = false;
      };
    }
  ];

  hardFailureSystem = mkSystem [
    ../../systems/server-test.nix
    {
      boot.initrd.systemd.services."mount-var".script = lib.mkForce ''
        echo "rfc0011-hard-edge: refusing the required var substrate" >&2
        exit 1
      '';
    }
  ];
in {
  name = "rfc-0011-degraded-boot";
  timeout = 1200;

  machines = {
    degraded = {
      system = degradedSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      memoryMiB = 4096;
      packages = [
        "desired-config-test"
        "desired-prune-test"
        "test-http-server"
      ];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "2G";
          aos.apm.desiredPackages = [
            "desired-config-test"
            "desired-prune-test"
            "test-http-server"
          ];
          desired-config-test.config.env.TOKEN = "desired-token";
        }
      '';
    };

    hard_edge = {
      system = hardFailureSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      memoryMiB = 2048;
      expectAgent = false;
    };
  };

  testScript =
    # python
    ''
      import hashlib
      import json
      import time
      from pathlib import Path

      APM = "${pkgs.aos}/bin/apm"
      JQ = "${pkgs.jq}/bin/jq"


      def current_generation():
          return int(degraded.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def canonical_hash(value):
          def string(value):
              body = ""
              for character in value:
                  if character == '"':
                      body += '\\"'
                  elif character == "\\":
                      body += "\\\\"
                  elif ord(character) < 0x20:
                      body += f"\\u{ord(character):04x}"
                  else:
                      body += character
              return '"' + body + '"'

          def encode(value):
              if value is None:
                  return "null"
              if value is True:
                  return "true"
              if value is False:
                  return "false"
              if isinstance(value, str):
                  return string(value)
              if isinstance(value, (int, float)):
                  return str(value).lower()
              if isinstance(value, list):
                  return "[" + ",".join(encode(item) for item in value) + "]"
              if isinstance(value, dict):
                  return "{" + ",".join(
                      string(key) + ":" + encode(value[key])
                      for key in sorted(value)
                  ) + "}"
              raise TypeError(type(value))

          encoded = encode(value).encode()
          return "sha256:" + hashlib.sha256(encoded).hexdigest()


      # Establish that the unmodified production eval and graph are healthy.
      degraded.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      degraded.succeed("systemctl is-active --quiet aos-config.target")
      degraded.succeed("systemctl is-active --quiet multi-user.target")
      degraded.succeed("systemctl is-active --quiet sshd.service")
      degraded.succeed("systemctl is-active --quiet desired-config-test.service")
      degraded.succeed("systemctl is-active --quiet desired-prune-test.service")
      degraded.succeed("systemctl is-active --quiet test-http-server.socket")
      degraded.succeed(
          "test \"$(cat /etc/aos/packages/desired-config-test/config.env)\" "
          "= TOKEN=desired-token"
      )
      first = current_generation()

      # Replace only one exact runtime output pin with a canonical-but-absent
      # store path. Keep its signed expose/config metadata and one blessed NAR
      # identity, so manifest validation accepts the pin and the real fetch
      # subverb is what fails. desired-prune-test is made dependent on it;
      # desired-config-test remains an independent healthy package.
      degraded.succeed(r'''
          set -eu
          bad=/nix/store/00000000000000000000000000000000-unreachable-output
          hash=00000000000000000000000000000000
          test ! -e "$bad"
          cp /run/aos/manifest.json /run/aos/full-intent-before-failure.json
          ${pkgs.jq}/bin/jq --arg bad "$bad" --arg hash "$hash" '
            .packageOutputs["test-http-server"] as $pin
            | ($pin.store_path | split("/")[3] | split("-")[0]) as $old_hash
            | ($pin.closure[]
                | select(.store_path_hash == $old_hash)
                | .realisations[0]) as $realisation
            | .ownership.storePaths as $owners
            | .storePaths = [
                .storePaths[]
                | select(($owners[.] // "") != "test-http-server")
              ]
            | .ownership.storePaths |= with_entries(
                select(.value != "test-http-server")
              )
            | .storePaths = ((.storePaths + [$bad]) | sort | unique)
            | .ownership.storePaths[$bad] = "test-http-server"
            | .packageOutputs["test-http-server"].store_path = $bad
            | .packageOutputs["test-http-server"].closure = [{
                store_path_hash: $hash,
                store_path: $bad,
                realisations: [$realisation]
              }]
            | .graph.edges["desired-prune-test"] = ["test-http-server"]
          ' /run/aos/full-intent-before-failure.json > /run/aos/manifest.json.new
          mv /run/aos/manifest.json.new /run/aos/manifest.json
          ${pkgs.jq}/bin/jq -c '.graph' /run/aos/manifest.json > /run/aos/graph.json.new
          mv /run/aos/graph.json.new /run/aos/graph.json
          rm -f /run/aos/activation.json /run/aos/source-manifest.json
          systemctl restart aos-graph-compile.service
      ''', timeout=420)

      # The template exhausted its real Restart=on-failure budget. Its failure
      # remained a soft Wants edge, so all umbrella targets and the compiler
      # completed and the host remained remotely manageable.
      fetch = degraded.succeed(
          "systemctl show aos-pkg-fetch@test-http-server.service "
          "-p ActiveState -p Result -p NRestarts -p Restart"
      )
      fetch_properties = dict(
          line.split("=", 1) for line in fetch.splitlines() if "=" in line
      )
      assert fetch_properties["ActiveState"] == "failed", fetch_properties
      assert fetch_properties["Result"] == "exit-code", fetch_properties
      assert fetch_properties["Restart"] == "on-failure", fetch_properties
      assert int(fetch_properties["NRestarts"]) >= 4, fetch_properties
      degraded.succeed("systemctl is-active --quiet aos-fetch.target")
      degraded.succeed("systemctl is-active --quiet aos-config-render.target")
      degraded.succeed("systemctl is-active --quiet aos-config.target")
      degraded.succeed("systemctl is-active --quiet aos-graph-compile.service")
      degraded.succeed("systemctl is-active --quiet multi-user.target")
      degraded.succeed("systemctl is-active --quiet sshd.service")
      assert degraded.succeed(
          "systemctl is-system-running 2>/dev/null || true"
      ).strip() == "degraded"

      # The independent package really traversed fetch + render for this exact
      # graph transaction and its config remains live. Continued agent command
      # success corroborates reachability after the degraded commit.
      degraded.succeed("test -s /run/aos/fetch/desired-config-test.ok")
      degraded.succeed("test -s /run/aos/render/desired-config-test.ok")
      degraded.succeed("systemctl is-active --quiet desired-config-test.service")
      degraded.succeed(
          "test \"$(cat /etc/aos/packages/desired-config-test/config.env)\" "
          "= TOKEN=desired-token"
      )

      generation = current_generation()
      assert generation != first, (first, generation)
      generation_dir = f"/var/lib/profiles/system/gen-{generation}"
      manifest = json.loads(degraded.succeed(f"cat {generation_dir}/manifest.json"))
      drops = json.loads(degraded.succeed(f"cat {generation_dir}/drop-set.json"))
      source_manifest = json.loads(degraded.succeed(
          "cat /run/aos/source-manifest.json"
      ))
      activation = json.loads(degraded.succeed("cat /run/aos/activation.json"))
      state = json.loads(degraded.succeed(
          "cat /var/lib/profiles/system/state.json"
      ))
      record = next(g for g in state["generations"] if g["number"] == generation)

      assert manifest["packages"] == ["desired-config-test"], manifest["packages"]
      assert set(manifest["packageOutputs"]) == {"desired-config-test"}
      assert manifest["graph"]["edges"] == {"desired-config-test": []}
      assert "aos/packages/desired-config-test/config.env" in manifest["etc"]
      assert all(
          owner != "test-http-server" and owner != "desired-prune-test"
          for family in manifest["ownership"].values()
          for owner in family.values()
      ), manifest["ownership"]
      assert drops["projected"] is True, drops
      assert drops["dropped"] == [
          {
              "package": "desired-prune-test",
              "reason": "dependency_dropped:test-http-server",
          },
          {"package": "test-http-server", "reason": "fetch_failed"},
      ], drops
      assert drops["source_manifest_hash"] == canonical_hash(source_manifest), drops
      assert record["manifest_hash"] == canonical_hash(manifest), record
      assert drops["source_manifest_hash"] != record["manifest_hash"], drops
      assert activation["generation"] == generation, activation
      assert activation["generation_id"] == record["manifest_hash"], activation
      assert activation["status"] == "degraded", activation
      assert activation["activation_exit"] == 6, activation
      assert activation["dropped_packages"] == [
          "desired-prune-test",
          "test-http-server",
      ], activation
      degraded.succeed(
          f"test \"$(cat {generation_dir}/generation-id)\" "
          f"= \"{record['manifest_hash']}\""
      )
      degraded.succeed(
          f"{JQ} -e --slurpfile committed {generation_dir}/manifest.json "
          "'.packages != $committed[0].packages' "
          "/run/aos/source-manifest.json >/dev/null"
      )

      # The independent negative machine never reaches the guest agent. The
      # serial transcript must show both the deliberately failed required
      # mount and systemd's emergency transition, rather than stage 2.
      hard_log = Path(hard_edge.serial_log_path)
      deadline = time.monotonic() + 180
      hard_text = ""
      while time.monotonic() < deadline:
          if hard_log.exists():
              hard_text = hard_log.read_text(errors="replace")
              if (
                  "rfc0011-hard-edge" in hard_text
                  and (
                      "emergency.target" in hard_text
                      or "Emergency Mode" in hard_text
                      or "emergency shell" in hard_text.lower()
                  )
              ):
                  break
          time.sleep(1)
      assert "rfc0011-hard-edge" in hard_text, hard_text[-8000:]
      assert (
          "emergency.target" in hard_text
          or "Emergency Mode" in hard_text
          or "emergency shell" in hard_text.lower()
      ), hard_text[-8000:]
      assert "hard_edge login:" not in hard_text, hard_text[-8000:]
    '';
}
