##! sops — Editor of encrypted structured files with age, PGP, and KMS keys
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  age,
  gnupg,
}: let
  version = "3.13.3";
  src = fetchurl {
    name = "sops-${version}.tar.gz";
    urls = ["https://github.com/getsops/sops/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-SYEcXtgPa01OmM75jj9zeEBqppL9dz37cq0bTfuUBEg=";
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

    pname = "sops";
    inherit version src;

    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-AoFd6Q7j3yfxLxLNlPkY81xmAeu/LbvgFvgD0Y5C9e0=";
    };
    goPackage = "./cmd/sops";
    goOutput = "sops";
    ldflags = "-s -w -X github.com/getsops/sops/v3/version.Version=${version}";

    # The PGP key source shells out to GnuPG. Resolve the default binary to
    # the source-built package so PGP-encrypted files work without a PATH
    # lookup; SOPS_GPG_EXEC still selects another binary explicitly.
    postPatch = ''
      sed -i 's|return "gpg"$|return "${gnupg}/bin/gpg"|' pgp/keysource.go
      sed -i 's|assert.Equal(t, "gpg", gpgBinary())|assert.Equal(t, "${gnupg}/bin/gpg", gpgBinary())|' \
        pgp/keysource_test.go
      grep -q 'return "${gnupg}/bin/gpg"' pgp/keysource.go
      grep -q '"${gnupg}/bin/gpg", gpgBinary()' pgp/keysource_test.go
    '';

    # The PGP unit tests use real keys through GnuPG. Like upstream's test
    # target, import the functional-test key into a private keyring first.
    buildDeps = [gnupg];
    runtimeDeps = [gnupg];
    preBuild = ''
      export HOME="$TMPDIR/home"
      mkdir -p "$HOME"
      ${gnupg}/bin/gpg --batch --import pgp/sops_functional_tests_key.asc
    '';

    # The Vault and AWS KMS suites start their servers through a Docker
    # daemon in TestMain, which the build sandbox does not provide. Every
    # other package, including the PGP and age key sources, is tested.
    goTestFlags = "$(go list ./... | grep -v -e '/hcvault$' -e '/kms$')";

    postInstall = ''
      mkdir -p "$out/share/licenses/sops"
      cp LICENSE "$out/share/licenses/sops/"
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A YAML document and a fixed age identity.";
        operation = "Encrypt the document to the identity's recipient and decrypt it again.";
        expected = "Values are encrypted at rest and decryption restores the original document.";
        # A published test-only identity keeps the probe deterministic; it
        # protects nothing beyond this fixture.
        files = {
          "identity.txt" = "AGE-SECRET-KEY-18CNX60NMY8DZ0YXDZXFJ5W4Y64UL2PDWYFC4SADS7ZQ824UDJYXSFV6CSS\n";
          "secrets.yaml" = "database:\n    password: hunter2\n";
          "probe.py" = ''
            import os, subprocess

            env = dict(os.environ, SOPS_AGE_KEY_FILE="identity.txt")
            recipient = "age19nrcv5cmkklxd55ntjcu9tj8gn3kggaadu2zjz63gzzay8lewycq4qddu2"
            encrypted = subprocess.run(
                ["@out@/bin/sops", "--disable-version-check", "encrypt",
                 "--age", recipient, "secrets.yaml"],
                capture_output=True, text=True, env=env, check=True,
            ).stdout
            assert "hunter2" not in encrypted
            assert "ENC[AES256_GCM," in encrypted
            with open("secrets.enc.yaml", "w") as handle:
                handle.write(encrypted)

            decrypted = subprocess.run(
                ["@out@/bin/sops", "--disable-version-check", "decrypt",
                 "secrets.enc.yaml"],
                capture_output=True, text=True, env=env, check=True,
            ).stdout
            assert decrypted == "database:\n    password: hunter2\n", decrypted
            print("sops age roundtrip passed")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "sops age roundtrip passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A YAML document without sops metadata.";
        operation = "Ask sops to decrypt the unencrypted document.";
        expected = "sops rejects the file because it carries no sops metadata.";
        files = {
          "plain.yaml" = "password: hunter2\n";
          "probe.py" = ''
            import subprocess, sys

            result = subprocess.run(
                ["@out@/bin/sops", "--disable-version-check", "decrypt", "plain.yaml"],
                capture_output=True,
            )
            assert result.returncode != 0
            assert b"hunter2" not in result.stdout
            sys.stderr.write("sops rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "sops rejected invalid input\n";
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
      age-roundtrip = testing.mkToolCheck {
        pname = "tool-sops";
        tool = self;
        extraDeps = [age];
        command = ''
          sops --disable-version-check --version
          age-keygen -o /tmp/identity.txt
          export SOPS_AGE_KEY_FILE=/tmp/identity.txt
          printf 'database:\n    password: hunter2\n' > /tmp/secrets.yaml
          sops --disable-version-check encrypt \
            --age "$(age-keygen -y /tmp/identity.txt)" \
            /tmp/secrets.yaml > /tmp/secrets.enc.yaml
          ! grep -q hunter2 /tmp/secrets.enc.yaml
          sops --disable-version-check decrypt /tmp/secrets.enc.yaml | grep -qx '    password: hunter2'
          echo "sops age roundtrip passed"
        '';
      };
    };

    meta = {
      description = "Editor of encrypted files supporting YAML, JSON, ENV, INI and binary formats";
      homepage = "https://getsops.io/";
      license = "MPL-2.0";
      mainProgram = "sops";
    };
  }
