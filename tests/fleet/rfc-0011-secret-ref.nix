# tests/fleet/rfc-0011-secret-ref.nix — runtime secretRef acceptance.
{
  pkgs,
  systems,
  ...
}: let
  secretSystem = systems.server-test.extendModules {
    modules = [
      {
        aos.packages.aos-rfc0011-secret = {
          package = pkgs.aos-rfc0011-secret;
          bundle = true;
          preset = false;
        };
      }
    ];
  };
in {
  name = "rfc-0011-secret-ref";
  timeout = 1200;

  machines.target = {
    system = secretSystem;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent" "aos-rfc0011-secret"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.apm.desiredPackages = [ "aos-rfc0011-secret" ];
        "aos-rfc0011-secret".credentials.join-token.ref =
          "system-credential:bootstrap-token";
        environment.etc."rfc0011-secret-generation".text = "one\n";
      }
    '';
    extraModules = [
      {
        systemd.services.rfc0011-system-credential = {
          description = "Provide the RFC-0011 platform system credential";
          wantedBy = ["sysinit.target"];
          before = ["aos-eval.service"];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            set -eu
            mkdir -p /run/credentials/@system
            printf '%s' rfc0011-secret-alpha \
              > /run/credentials/@system/bootstrap-token
            chmod 0600 /run/credentials/@system/bootstrap-token
          '';
        };

        systemd.services.aos-eval = {
          requires = ["rfc0011-system-credential.service"];
          after = ["rfc0011-system-credential.service"];
        };
      }
    ];
  };

  testScript =
    # python
    ''
      import base64
      import json

      APM = "${pkgs.aos}/bin/apm"
      JQ = "${pkgs.jq}/bin/jq"
      SOURCE = "/run/credstore/rfc0011/join-token"
      ALPHA = "rfc0011-secret-alpha"
      BETA = "rfc0011-secret-beta"


      def current_generation():
          return int(target.succeed(
              f"{JQ} -er '.current' /var/lib/profiles/system/state.json"
          ).strip())


      def assert_no_plaintext(generation, *values):
          manifest = target.succeed("cat /run/aos/manifest.json")
          retained = target.succeed(
              f"cat /var/lib/profiles/system/gen-{generation}/manifest.json"
          )
          for value in values:
              assert value not in manifest, "plaintext credential leaked into live manifest"
              assert value not in retained, "plaintext credential leaked into retained manifest"
              target.succeed(f"""
                  if ${pkgs.grep}/bin/grep -R -F -- {value} \
                    /var/lib/profiles/system/gen-{generation}; then
                    echo 'plaintext credential leaked into generation files' >&2
                    exit 1
                  fi
              """)


      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-graph-compile.service", timeout=300
      )
      target.succeed("systemctl is-active --quiet aos-credential-recovery.service")
      recovery_before = target.succeed(
          "systemctl show -P Before aos-credential-recovery.service"
      ).split()
      assert "aos-eval.service" in recovery_before, recovery_before
      assert "sysinit.target" in recovery_before, recovery_before
      target.succeed(
          "test \"$(stat -c %a /var/lib/apm/credential-transactions)\" = 700"
      )
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-rfc0011-secret.service", timeout=120
      )
      first = current_generation()
      target.succeed(f"test \"$(cat {SOURCE})\" = {ALPHA}")
      target.succeed(f"test \"$(stat -c %a {SOURCE})\" = 600")
      target.succeed(f"test \"$(cat /run/aos-rfc0011-secret-observed)\" = {ALPHA}")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-start-count)\" = 1")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-attempt-count)\" = 1")
      # systemd mounted a private credential file before ExecStart; the
      # consumer records its delivery mode while the namespace exists.
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-delivery-mode)\" = 400")

      manifest = json.loads(target.succeed("cat /run/aos/manifest.json"))
      reference = manifest["credentials"]["aos-rfc0011-secret"]["join-token"]
      assert reference == {
          "name": "join-token",
          "source": SOURCE,
          "encrypted": False,
          "units": ["aos-rfc0011-secret.service"],
          "ref": "system-credential:bootstrap-token",
      }, reference
      assert_no_plaintext(first, ALPHA)

      # Rotate only the platform system credential. A new host generation
      # causes the same secretRef to resolve again; changed bytes are written
      # atomically before the consumer is restarted exactly once.
      target.succeed(f"""
          printf '%s' {BETA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      second_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        \"aos-rfc0011-secret\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"rfc0011-secret-generation\".text = \"two\\n\";
      }
      """
      encoded = base64.b64encode(second_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-two.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-secret-two.nix \
            --eval-root /run/rfc0011-secret-switch
      """, timeout=300)

      second = current_generation()
      assert second != first, (first, second)
      target.succeed(f"test \"$(cat {SOURCE})\" = {BETA}")
      target.succeed(f"test \"$(stat -c %a {SOURCE})\" = 600")
      target.succeed(f"test \"$(cat /run/aos-rfc0011-secret-observed)\" = {BETA}")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-start-count)\" = 2")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-attempt-count)\" = 2")
      target.succeed("systemctl is-active --quiet aos-rfc0011-secret.service")
      assert_no_plaintext(second, ALPHA, BETA)

      # A same-ABI retained-generation rollback must traverse the same
      # credential barrier. Rotate the platform source again without
      # re-evaluation, reactivate the retained generation, and prove that the
      # old direct path cannot leave the newer published bytes behind.
      target.succeed(f"""
          printf '%s' {ALPHA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
          {APM} rollback --system --generation {first}
      """, timeout=300)
      assert current_generation() == first
      target.succeed(f"test \"$(cat {SOURCE})\" = {ALPHA}")
      target.succeed(f"test \"$(cat /run/aos-rfc0011-secret-observed)\" = {ALPHA}")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-start-count)\" = 3")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-attempt-count)\" = 3")
      target.succeed("systemctl is-active --quiet aos-rfc0011-secret.service")
      assert_no_plaintext(first, ALPHA, BETA)

      # Credential rotation never activates a stopped consumer. Removing the
      # authenticated handle then prunes the previously managed source while
      # leaving that consumer in its exact pre-transaction state.
      target.succeed("systemctl stop aos-rfc0011-secret.service")
      target.succeed(f"""
          printf '%s' {BETA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      inactive_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        \"aos-rfc0011-secret\".credentials.join-token.ref =
          \"system-credential:bootstrap-token\";
        environment.etc.\"rfc0011-secret-generation\".text = \"inactive\\n\";
      }
      """
      encoded = base64.b64encode(inactive_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-inactive.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-secret-inactive.nix \
            --eval-root /run/rfc0011-secret-inactive-switch
      """, timeout=300)
      target.fail("systemctl is-active --quiet aos-rfc0011-secret.service")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-start-count)\" = 3")
      target.succeed(f"test \"$(cat {SOURCE})\" = {BETA}")

      removed_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"2G\";
        aos.apm.desiredPackages = [ \"aos-rfc0011-secret\" ];
        environment.etc.\"rfc0011-secret-generation\".text = \"removed\\n\";
      }
      """
      encoded = base64.b64encode(removed_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-secret-removed.nix"
      )
      target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-secret-removed.nix \
            --eval-root /run/rfc0011-secret-removed-switch
      """, timeout=300)
      target.fail("systemctl is-active --quiet aos-rfc0011-secret.service")
      target.succeed("test \"$(cat /run/aos-rfc0011-secret-start-count)\" = 3")
      target.succeed(f"test ! -e {SOURCE}")
    '';
}
