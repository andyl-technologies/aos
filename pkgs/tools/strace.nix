##! strace — System call tracer for Linux
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  gnumake,
  linux-headers,
}: let
  version = "7.2";
  isLinuxCross = stdenv.isCross && stdenv.hostPlatform.isLinux;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "strace";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Strace records the successful exit_group call.";
        "files" = {
          "verify.py" = "trace = open(\"trace.log\", encoding=\"utf-8\").read()\nassert \"exit_group(0)\" in trace\nprint(\"strace observation passed\")\n";
        };
        "input" = "A child shell that exits successfully without other work.";
        "operation" = "Trace only the child's exit_group system call into a local trace file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/strace"
              "-qq"
              "-e"
              "trace=exit_group"
              "-o"
              "trace.log"
              "@bash@"
              "-c"
              "exit 0"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@python@"
              "verify.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "strace observation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Strace rejects the unknown syscall before starting the child.";
        "files" = {};
        "input" = "A syscall filter naming a syscall that does not exist.";
        "operation" = "Parse the invalid trace expression.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/strace"
              "-e"
              "trace=qualification_missing_syscall"
              "@bash@"
              "-c"
              "exit 0"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
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
        "https://github.com/strace/strace/releases/download/v${version}/strace-${version}.tar.xz"
      ];
      hash = "sha256-S95iRpJokNzugk9uasQqBnUvR9d+UJfYbjwNbUtwn+U=";
    };

    buildDeps = [gnumake] ++ lib.optionals (!isLinuxCross) [linux-headers];
    runtimeDeps = [];
    propagatedDeps = [];

    # strace builds with -Werror and uses trailing zero-length arrays as
    # flexible members; -fstrict-flex-arrays=3 then trips -Werror=array-bounds
    # (e.g. mmsghdr.c). Step down to level 1 (still hardened, but [0]/[1]
    # trailing arrays stay flexible). Same idiom as elfutils.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd strace-${version}
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString isLinuxCross ''
            # Kernel declarations describe the traced target, not the build
            # machine selected by executable build-dependency splicing.
            export C_INCLUDE_PATH="${linux-headers}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
          ''
          + ''
            ./configure \
              --prefix=$out \
              --disable-mpers \
              --enable-static=no
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "System call tracer for Linux";
      homepage = "https://strace.io/";
      license = "LGPL-2.1-or-later";
    };
  }
