##! Typed named-credential resolution and delivery lifecycle acceptance.
{
  pkgs,
  systems,
  ...
}: let
  secretSystem = systems.server-test.extendModules {
    modules = [
      {
        aos.packages.aos-credential-delivery-test = {
          package = pkgs.aos-credential-delivery-test;
          bundle = true;
        };
        "aos-credential-delivery-test".enable = false;
      }
    ];
  };
in {
  name = "credential-delivery";
  timeout = 1200;

  machines.target = {
    system = secretSystem;
    bootMode = "image";
    imageDiskMiB = 16384;
    memoryMiB = 4096;
    packages = ["aos-test-agent" "aos-credential-delivery-test"];
    metadata."host.nix" = ''
      {
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
      }
    '';
  };

  testScript =
    # python
    ''
      import base64
      import json

      APM = "${pkgs.aos.apm}/bin/apm"
      FIND = "${pkgs.findutils}/bin/find"
      STATE = "/var/lib/aos-pkg-aos-credential-delivery-test"
      ALPHA = "credential-delivery-test-alpha"
      BETA = "credential-delivery-test-beta"


      def write_host(name, text):
          encoded = base64.b64encode(text.encode()).decode()
          path = f"/run/credential-delivery-test-{name}.nix"
          target.succeed(f"printf '%s' {encoded} | base64 -d > {path}")
          return path


      def switch(name, text):
          host = write_host(name, text)
          target.succeed(
              f"{APM} switch --from {host} --eval-root /run/{name}-eval",
              timeout=300,
          )


      def delivered_path():
          paths = target.succeed(
              f"{FIND} /run/aos/credential-views -type f -name join-token"
          ).split()
          assert len(paths) == 1, paths
          return paths[0]


      def assert_no_plaintext(*values):
          manifest = target.succeed("cat /run/aos/manifest.json")
          parsed = json.loads(manifest)
          assert "credentials" not in parsed, parsed.keys()
          for value in values:
              assert value not in manifest, "credential bytes leaked into the manifest"


      target.wait_for_unit("aos-eval.service", timeout=300)
      target.succeed(f"""
          mkdir -p /run/credentials/@system
          printf '%s' {ALPHA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      first = """{
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.apm.desiredPackages = [ "aos-credential-delivery-test" ];
        "aos-credential-delivery-test" = {
          enable = true;
          credentialName = "bootstrap-token";
          restartToken = "one";
        };
      }
      """
      switch("credential-first", first)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-credential-delivery-test.service",
          timeout=120,
      )
      source = delivered_path()
      target.succeed(f"test \"$(cat {source})\" = {ALPHA}")
      target.succeed(f"test \"$(stat -c %a {source})\" = 400")
      target.succeed(f"test \"$(cat {STATE}/observed)\" = {ALPHA}")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 1")
      assert target.succeed(f"cat {STATE}/delivery-mode").strip() == "400"
      assert_no_plaintext(ALPHA)

      target.succeed(f"""
          printf '%s' {BETA} > /run/credentials/@system/bootstrap-token
          chmod 0600 /run/credentials/@system/bootstrap-token
      """)
      second = """{
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.apm.desiredPackages = [ "aos-credential-delivery-test" ];
        "aos-credential-delivery-test" = {
          enable = true;
          credentialName = "bootstrap-token";
          restartToken = "two";
        };
      }
      """
      switch("credential-rotation", second)
      target.wait_until_succeeds(
          f"test \"$(cat {STATE}/observed)\" = {BETA}", timeout=120
      )
      assert delivered_path() == source
      target.succeed(f"test \"$(cat {source})\" = {BETA}")
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 2")
      assert_no_plaintext(ALPHA, BETA)

      removed = """{
        aos.provisioning.storage.partitions.var.sizeMin = "2G";
        aos.apm.desiredPackages = [ "aos-credential-delivery-test" ];
        "aos-credential-delivery-test".enable = false;
      }
      """
      switch("credential-revocation", removed)
      target.wait_until_fails(
          "systemctl is-active --quiet aos-credential-delivery-test.service",
          timeout=120,
      )
      target.succeed(
          f"test -z \"$({FIND} /run/aos/credential-views -type f -name join-token -print -quit)\""
      )
      target.succeed(f"test \"$(cat {STATE}/start-count)\" = 2")
    '';
}
