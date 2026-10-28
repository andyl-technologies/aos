##! age — Simple, modern file encryption with small explicit keys
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "1.3.2";
  src = fetchurl {
    name = "age-${version}.tar.gz";
    urls = ["https://github.com/FiloSottile/age/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-sHwoxsS9r6JyBzoxC3W8IsSdqJBFhaicMOXKQjPmOEM=";
  };

  # Every command shares one version stamp; `age --version` reports it
  # instead of the module pseudo-version a tarball build would embed.
  ldflags = "-s -w -X main.Version=v${version}";

  # The encryption tool is the package entry point. The key generator,
  # header inspector, and passphrase-batch plugin are separate programs.
  companionCommands = ["age-keygen" "age-inspect" "age-plugin-batchpass"];
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

    pname = "age";
    inherit version src;

    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-9rEWpc40zBpmETZRozBD8TD9Q0HONGV4gpTCrlXoU70=";
    };
    goPackage = "./cmd/age";
    goOutput = "age";
    inherit ldflags;

    postBuild =
      lib.concatMapStrings (command: ''
        go build -ldflags "${ldflags}" -o ${command} ./cmd/${command}
      '')
      companionCommands;

    postInstall = ''
      install -m 755 ${lib.concatStringsSep " " companionCommands} "$out/bin/"

      mkdir -p "$out/share/man/man1" "$out/share/licenses/age"
      cp doc/*.1 "$out/share/man/man1/"
      cp LICENSE "$out/share/licenses/age/"
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A short plaintext and a newly generated X25519 identity.";
        operation = "Generate an identity, encrypt to its recipient, and decrypt the result.";
        expected = "Decryption returns the original plaintext unchanged.";
        files = {
          "message.txt" = "answer=42\n";
        };
        steps = [
          {
            argv = ["@out@/bin/age-keygen" "-o" "identity.txt"];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["@out@/bin/age-keygen" "-y" "-o" "recipient.txt" "identity.txt"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/age" "-R" "recipient.txt" "-o" "message.age" "message.txt"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/age" "-d" "-i" "identity.txt" "message.age"];
            exit_code = 0;
            stdout.exact = "answer=42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A file that is not an age-encrypted payload.";
        operation = "Decrypt the malformed file with a valid identity.";
        expected = "age rejects the header and writes no plaintext.";
        files = {
          "not-age.txt" = "plain text, not an age header\n";
        };
        steps = [
          {
            argv = ["@out@/bin/age-keygen" "-o" "identity.txt"];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess, sys

                result = subprocess.run(
                    ["@out@/bin/age", "-d", "-i", "identity.txt", "not-age.txt"],
                    capture_output=True,
                )
                assert result.returncode != 0
                assert result.stdout == b""
                sys.stderr.write("age rejected invalid input\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "age rejected invalid input\n";
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
      roundtrip = testing.mkToolCheck {
        pname = "tool-age";
        tool = self;
        command = ''
          age --version
          age-keygen -o /tmp/identity.txt
          age-keygen -y /tmp/identity.txt > /tmp/recipient.txt
          echo answer=42 | age -R /tmp/recipient.txt -a > /tmp/message.age
          age-inspect /tmp/message.age
          age -d -i /tmp/identity.txt /tmp/message.age
        '';
      };
    };

    meta = {
      description = "Simple, modern, and secure file encryption tool and format";
      homepage = "https://age-encryption.org/";
      license = "BSD-3-Clause";
      mainProgram = "age";
    };
  }
