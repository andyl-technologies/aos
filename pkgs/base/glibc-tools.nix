##! glibc-tools — complete libc utilities using distribution interpreters
{
  mkDerivation,
  glibc,
  perl,
  bash,
}: let
  version = glibc.version;
in
  mkDerivation {
    pname = "glibc-tools";
    inherit version;

    buildDeps = [glibc.bin];
    runtimeDeps = [glibc perl bash];
    dontNukeRefs = true;

    passthru.evidenceSources = glibc.passthru.evidenceSources;

    phases = [
      {
        name = "install";
        script = ''
          cp -R ${glibc.bin}/. "$out/"
          chmod -R u+w "$out"

          # The bootstrap utility export deliberately uses its tier's Perl.
          # Rebind mtrace to the distribution interpreter without losing tools.
          construction_perl=$(head -n 1 "$out/bin/mtrace" | sed 's/^#! *//')
          test -n "$construction_perl"
          sed -i "s|$construction_perl|${perl}/bin/perl|g" "$out/bin/mtrace"

          # xtrace locates its companion programs through the utility export.
          sed -i "s|${glibc.bin}/|$out/|g" "$out/bin/xtrace"
        '';
      }
    ];

    meta = {
      description = "Complete GNU C Library utilities with distribution interpreters";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build.os = "linux";
      execute.os = "linux";
    };
  }
