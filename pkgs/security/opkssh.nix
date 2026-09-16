##! opkssh — OpenPubkey SSH authentication
##!
##! Enables SSH authentication using OpenID Connect (OIDC) identities.
##! Users authenticate via their identity provider (Google, Azure, GitLab)
##! and receive ephemeral SSH keys containing PK Tokens. The SSH daemon
##! verifies these tokens via an AuthorizedKeysCommand.
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "0.16.0";
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "opkssh";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents its invocation contract.";
        "files" = {};
        "input" = "The packaged opkssh command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/opkssh\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"usage\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"opkssh operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "opkssh operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing external I/O.";
        "files" = {};
        "input" = "A opkssh invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without accessing a device or service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/opkssh\", \"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"opkssh rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "opkssh rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/openpubkey/opkssh/archive/v${version}/opkssh-${version}.tar.gz"
      ];
      hash = "sha256-t8Mmsk1v6XBW1Fny1e9+r7JYkLcCeVN3RqNoRn/i3Ds=";
    };

    goModules = fetchGoModules {
      src = fetchurl {
        urls = [
          "https://github.com/openpubkey/opkssh/archive/v${version}/opkssh-${version}.tar.gz"
        ];
        hash = "sha256-t8Mmsk1v6XBW1Fny1e9+r7JYkLcCeVN3RqNoRn/i3Ds=";
      };
      hash = "sha256-p9FvUta7eqkc8y8zzhwnAVAKEbdX4aWE6L6f/F+hEKQ=";
    };

    goPackage = ".";
    goOutput = "opkssh";
    ldflags = "-s -w -X main.Version=${version}";
    doCheck = false;

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-opkssh";
        tool = self;
        command = "opkssh --version";
      };
    };

    meta = {
      description = "opkssh — SSH authentication using OpenID Connect identities";
      homepage = "https://github.com/openpubkey/opkssh";
      license = "Apache-2.0";
    };
  }
