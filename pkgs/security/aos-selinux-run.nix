##! aos-selinux-run - Enter a SELinux context before exec
{lib, mkDerivation}:
mkDerivation {
  pname = "aos-selinux-run";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The wrapper returns success and describes the required context and command boundary.";
      "files" = {};
      "input" = "A request for the SELinux transition wrapper's command contract.";
      "operation" = "Invoke its help path without attempting a security transition.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess\nresult = subprocess.run([\"@out@/bin/aos-selinux-run\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0\nassert result.stdout == \"usage: aos-selinux-run --context CONTEXT -- COMMAND [ARG...]\\n\"\nprint(\"aos-selinux-run operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "aos-selinux-run operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The wrapper rejects the request before touching the SELinux process attribute.";
      "files" = {};
      "input" = "A transition request with a context but no command after the separator.";
      "operation" = "Parse the incomplete transition request.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-selinux-run\", \"--context\", \"aos_test_t\", \"--\"], capture_output=True, text=True)\nassert result.returncode == 2 and \"missing command after --\" in result.stderr\nsys.stderr.write(\"aos-selinux-run rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "aos-selinux-run rejected invalid input\n";
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

  buildDeps = [];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -Werror \
          -o $out/bin/aos-selinux-run ${./aos-selinux-run.c}
      '';
    }
  ];

  passthru.evidenceSources = [
    (builtins.path {
      path = ./aos-selinux-run.nix;
      name = "aos-selinux-run.nix";
    })
    (builtins.path {
      path = ./aos-selinux-run.c;
      name = "aos-selinux-run.c";
    })
  ];

  meta = {
    description = "Enter a SELinux context before exec";
    license = "MIT";
  };
}
