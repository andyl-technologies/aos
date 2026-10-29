##! opentofu — Open-source infrastructure as code tool (the `tofu` CLI)
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  bash,
  git,
}: let
  # OpenTofu 1.13.2 requires Go 1.27.3, newer than the self-hosted AOS
  # compiler. Keep the newest release whose declared toolchain floor is met.
  version = "1.13.1";
  src = fetchurl {
    name = "opentofu-${version}.tar.gz";
    urls = ["https://github.com/opentofu/opentofu/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-VMU089HfJTQwzAIiDZS5HB1WPpXwQLwk0ppMRbwZeDg=";
  };
in
  mkGoPackage {
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

    pname = "opentofu";
    # OpenTofu keeps configuration and state compatible within the 1.x series.
    # https://opentofu.org/docs/language/v1-compatibility-promises/
    inherit version src;

    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-a9mp/v6RUEVpyFMvy+YBHven1+gwcIItytgKum9rigY=";
    };
    goPackage = "./cmd/tofu";
    goOutput = "tofu";
    # Match upstream release builds: a final version without the -dev marker
    # and without the official-build flag reserved for upstream artifacts.
    ldflags = "-s -w -X github.com/opentofu/opentofu/version.dev=no";

    # Module installer and backend tests create local Git repositories, and
    # the credentials-helper test executes a shell script from testdata.
    buildDeps = [git];

    # The local-exec provisioner runs commands through a hard-coded /bin/sh.
    # Use the source-built shell instead, and update the tests that assert
    # the interpreter in their expected output.
    runtimeDeps = [bash];
    postPatch = ''
      patchShebangs internal/command/cliconfig/svcauthconfig/testdata

      for file in \
        internal/builtin/provisioners/local-exec/resource_provisioner.go \
        internal/builtin/provisioners/local-exec/resource_provisioner_test.go \
        internal/command/e2etest/primary_test.go
      do
        sed -i 's|\(\[\]string{\)"/bin/sh"|\1"${bash}/bin/sh"|; s|\[\\"/bin/sh\\"|[\\"${bash}/bin/sh\\"|g; s|\["/bin/sh"|["${bash}/bin/sh"|g' "$file"
        ! grep -q '"/bin/sh\\\?"' "$file"
      done
    '';
    preBuild = ''
      export HOME="$TMPDIR/home"
      mkdir -p "$HOME"
    '';

    postInstall = ''
      mkdir -p "$out/share/licenses/opentofu"
      cp LICENSE "$out/share/licenses/opentofu/"
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A configuration with a local value and an output, using no providers.";
        operation = "Initialize the working directory and apply the configuration.";
        expected = "OpenTofu records the computed output in local state.";
        files = {
          "main.tf" = ''
            locals {
              greeting = upper("aos")
            }

            output "greeting" {
              value = "''${local.greeting}-''${length([1, 2, 3])}"
            }
          '';
          "probe.py" = ''
            import os, subprocess

            env = dict(os.environ, HOME=os.getcwd(), TF_IN_AUTOMATION="1")
            for argv in (["init", "-input=false"],
                         ["apply", "-auto-approve", "-input=false"]):
                subprocess.run(["@out@/bin/tofu", *argv], check=True,
                               capture_output=True, env=env)
            output = subprocess.run(
                ["@out@/bin/tofu", "output", "-raw", "greeting"],
                check=True, capture_output=True, text=True, env=env,
            ).stdout
            assert output == "AOS-3", output
            print("tofu apply passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "tofu apply passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A configuration file with an unclosed block.";
        operation = "Check the file with tofu fmt.";
        expected = "OpenTofu reports the HCL syntax error and leaves the file unchanged.";
        files = {
          "main.tf" = "output \"broken\" {\n  value = 1\n";
          "probe.py" = ''
            import os, subprocess, sys

            env = dict(os.environ, HOME=os.getcwd())
            result = subprocess.run(
                ["@out@/bin/tofu", "fmt", "-check", "main.tf"],
                capture_output=True, env=env,
            )
            assert result.returncode != 0
            with open("main.tf") as handle:
                assert handle.read() == 'output "broken" {\n  value = 1\n'
            sys.stderr.write("tofu rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "tofu rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };

    checks = {
      testing,
      self,
      ...
    }: {
      apply = testing.mkToolCheck {
        pname = "tool-opentofu";
        tool = self;
        command = ''
          export HOME=/tmp
          tofu version | grep -qx 'OpenTofu v${version}'
          mkdir -p /tmp/work
          cd /tmp/work
          printf 'output "answer" {\n  value = 6 * 7\n}\n' > main.tf
          tofu init -input=false
          tofu apply -auto-approve -input=false
          test "$(tofu output -raw answer)" = 42
          echo "tofu apply passed"
        '';
      };
    };

    meta = {
      description = "Declarative infrastructure as code tool, a community fork of Terraform";
      homepage = "https://opentofu.org/";
      license = "MPL-2.0";
      mainProgram = "tofu";
    };
  }
