##! opentofu-providers — Offline filesystem mirror of common source-built providers
#
# Point OpenTofu at the mirror to initialize configurations without a
# registry:
#
# ```text
# export TF_CLI_CONFIG_FILE=<this package>/share/opentofu/tofurc
# tofu init
# ```
#
# `passthru.mkProvider` builds another provider from source and
# `passthru.mkMirror` merges a chosen provider list into a new mirror.
{
  lib,
  callPackage,
  jq,
  opentofu,
}: let
  mkProvider = callPackage ./_opentofu/provider.nix {};
  mkMirror = callPackage ./_opentofu/mirror.nix {};
  providers = import ./_opentofu/providers.nix {inherit mkProvider jq;};
  providerList = builtins.attrValues providers;

  # One release identity for the bundled set: bump it with any provider.
  version = "2026.10.0";
in
  mkMirror {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };

    pname = "opentofu-providers";
    inherit version;
    providers = providerList;
    description = "Offline filesystem mirror of common source-built OpenTofu providers";

    passthru = {
      inherit providers mkProvider mkMirror;
    };

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The packaged provider mirror and its CLI configuration.";
        operation = "Inspect every mirrored provider and start each plugin outside OpenTofu.";
        expected = "Each provider is an executable plugin that refuses direct use, and the configuration names the mirror.";
        files = {
          "probe.py" = ''
            import glob, os, subprocess

            root = "@out@/share/opentofu/plugins/registry.opentofu.org/hashicorp"
            found = set()
            for path in glob.glob(root + "/*/*/*/terraform-provider-*"):
                assert os.access(path, os.X_OK), path
                result = subprocess.run([path], capture_output=True, text=True)
                assert result.returncode == 1, (path, result.returncode)
                assert "This binary is a plugin" in result.stderr, result.stderr
                found.add(path.split("/")[-4])
            expected = {${lib.concatMapStringsSep ", " (name: ''"${name}"'') (builtins.attrNames providers)}}
            assert found == expected, found

            with open("@out@/share/opentofu/tofurc") as handle:
                config = handle.read()
            assert "@out@/share/opentofu/plugins" in config, config
            print("opentofu provider mirror passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "opentofu provider mirror passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An unknown command-line flag passed to a mirrored provider.";
        operation = "Start the null provider with the unsupported flag.";
        expected = "The provider rejects the flag before serving the plugin protocol.";
        files = {
          "probe.py" = ''
            import glob, subprocess, sys

            pattern = "@out@/share/opentofu/plugins/registry.opentofu.org/hashicorp/null/*/*/terraform-provider-null_*"
            (provider,) = glob.glob(pattern)
            result = subprocess.run([provider, "-aos-invalid-flag"], capture_output=True)
            assert result.returncode == 2, result.returncode
            sys.stderr.write("opentofu provider rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "opentofu provider rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };

    # The VM has no network, so a successful init proves every provider came
    # from the source-built mirror rather than a registry.
    checks = {
      testing,
      self,
      ...
    }: {
      offline-init = testing.mkToolCheck {
        pname = "opentofu-providers-offline-init";
        tool = self;
        extraDeps = [opentofu];
        command = ''
          export HOME=/tmp
          export TF_CLI_CONFIG_FILE=${self}/share/opentofu/tofurc
          export TF_IN_AUTOMATION=1
          mkdir -p /tmp/work
          cd /tmp/work
          cat > main.tf <<'EOF'
          terraform {
            required_providers {
              null   = { source = "hashicorp/null" }
              random = { source = "hashicorp/random" }
              local  = { source = "hashicorp/local" }
              tls    = { source = "hashicorp/tls" }
              http   = { source = "hashicorp/http" }
            }
          }

          resource "random_pet" "name" {}

          resource "tls_private_key" "key" {
            algorithm = "ED25519"
          }

          resource "local_file" "greeting" {
            filename = "''${path.module}/greeting.txt"
            content  = "hello ''${random_pet.name.id}"
          }

          resource "null_resource" "done" {
            triggers = {
              file = local_file.greeting.id
              key  = tls_private_key.key.public_key_fingerprint_sha256
            }
          }
          EOF
          tofu init -input=false
          grep -q 'registry.opentofu.org/hashicorp/tls' .terraform.lock.hcl
          tofu validate
          tofu apply -auto-approve -input=false
          grep -q '^hello ' greeting.txt
          echo "opentofu offline init passed"
        '';
      };
    };
  }
