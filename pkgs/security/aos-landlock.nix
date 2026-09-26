##! aos-landlock — Apply package Landlock rules before exec
{
  lib,
  mkDerivation,
  linux-headers,
}:
mkDerivation {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
    target = [];
    role = "public-package";
  };
  pname = "aos-landlock";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The wrapper returns success and documents its filesystem and network policy options.";
      "files" = {};
      "input" = "The Landlock wrapper's command-line interface.";
      "operation" = "Request its help without creating a kernel ruleset.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess\nresult = subprocess.run([\"@out@/bin/aos-landlock\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"--fs-ro\" in result.stdout and \"--tcp-connect\" in result.stdout\nprint(\"aos-landlock operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "aos-landlock operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The wrapper rejects mutually incompatible network options before execution.";
      "files" = {};
      "input" = "A request combining unrestricted networking with a restricted TCP bind port.";
      "operation" = "Parse the contradictory network policy.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-landlock\", \"--network-unrestricted\", \"--tcp-bind\", \"8080\", \"--\", \"@bash@\", \"-c\", \"exit 0\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-landlock rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "aos-landlock rejected invalid input\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

  version = "0";
  src = null;

  buildDeps = [linux-headers];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -Werror \
          -I${linux-headers}/include \
          -o $out/bin/aos-landlock ${./aos-landlock.c}
      '';
    }
  ];

  passthru.evidenceSources = [
    (builtins.path {
      path = ./aos-landlock.nix;
      name = "aos-landlock.nix";
    })
    (builtins.path {
      path = ./aos-landlock.c;
      name = "aos-landlock.c";
    })
  ];

  checks = {
    testing,
    self,
    pkgs,
  }: {
    fs = testing.mkVMTest {
      name = "security-aos-landlock-fs";
      rootfsDeps = [
        self
        pkgs.coreutils
      ];
      testScript = ''
        abi=$(aos-landlock --print-abi)
        test "$abi" -ge 4
        echo "aos-landlock max ABI: $abi"

        mkdir -p /tmp/aos-landlock-allow /tmp/aos-landlock-deny
        printf original > /tmp/aos-landlock-exact-file

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-allow \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-landlock-allow/ok
        test -f /tmp/aos-landlock-allow/ok

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-exact-file \
          -- /bin/sh -c 'printf updated > /tmp/aos-landlock-exact-file'
        test "$(cat /tmp/aos-landlock-exact-file)" = updated

        aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /dev/null \
          -- /bin/sh -c 'printf quiet > /dev/null'

        aos-landlock --require-abi 4 \
          --network-unrestricted \
          --fs-ro / \
          --fs-rw /dev/null \
          -- /bin/sh -c 'printf unrestricted > /dev/null'

        if aos-landlock --network-unrestricted --tcp-bind 8080 \
          -- ${pkgs.coreutils}/bin/true; then
          echo "FAIL: aos-landlock accepted unrestricted networking with TCP rules" >&2
          exit 1
        fi

        if aos-landlock --require-abi 4 \
          --fs-ro / \
          --fs-rw /tmp/aos-landlock-allow \
          -- ${pkgs.coreutils}/bin/touch /tmp/aos-landlock-deny/nope; then
          echo "FAIL: aos-landlock allowed write outside fs-rw grant" >&2
          exit 1
        fi

        echo "aos-landlock fs policy: PASS"
      '';
    };
  };

  meta = {
    description = "Apply package Landlock rules before exec";
    license = "MIT";
  };
}
