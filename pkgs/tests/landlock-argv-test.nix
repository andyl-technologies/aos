{
  mkDerivation,
  writeShellScriptBin,
}: let
  recorder = writeShellScriptBin "landlock-argv-test-recorder" ''
    set -eu

    out=/var/lib/aos-pkg-landlock-argv-test/argv
    : > "$out"
    printf 'argc=%s\n' "$#" >> "$out"

    i=0
    for arg in "$@"; do
      i=$((i + 1))
      printf 'arg%s=<%s>\n' "$i" "$arg" >> "$out"
    done
  '';
in
  mkDerivation {
    pname = "landlock-argv-test";
    version = "1.0.0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/landlock-argv-test"
          printf landlock-argv-test > "$out/share/landlock-argv-test/payload.txt"
        '';
      }
    ];

    expose = {
      units."landlock-argv-test.service" = {
        description = "AOS Landlock argv preservation test";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${recorder}/bin/landlock-argv-test-recorder plain 'two words' 'semi;colon' 'quote\"inner' 'colon:value'";
          RemainAfterExit = true;
          StateDirectory = "aos-pkg-landlock-argv-test";
        };
      };

      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
    };

    meta.description = "AOS Landlock exec argv preservation test payload";
  }
