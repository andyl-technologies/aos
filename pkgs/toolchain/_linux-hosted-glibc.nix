##! Publishes target libc outputs after their script interpreters exist.
{
  mkDerivation,
  stdenv,
  buildPackages,
  bash,
  perl,
}: let
  libc = stdenv.glibc;
in
  mkDerivation {
    pname = "glibc";
    version = "2.39";
    src = null;
    outputs = ["out" "bin" "dev" "static" "getent"];
    runtimeDeps = [bash perl libc];
    dontStrip = true;
    dontNukeRefs = true;
    passthru.evidenceSources = libc.passthru.evidenceSources;

    # The libc itself must exist before target Bash and Perl can be built.
    # Complete its executable interface separately, preserving the original
    # library/header outputs used by the cross compiler and those interpreters.
    disallowedReferences = [
      libc.bin
      buildPackages.bash
      buildPackages.perl
    ];

    phases = [
      {
        name = "install";
        script = ''
          # Forward the source-built library and data outputs. Keeping every
          # public output on this derivation also makes output selectors use
          # the completed utilities rather than the construction-stage scripts.
          mkdir -p "$out" "$dev" "$static" "$getent"
          rmdir "$out" "$dev" "$static" "$getent"
          ln -s ${libc} "$out"
          ln -s ${libc.dev} "$dev"
          ln -s ${libc.static} "$static"
          ln -s ${libc.getent} "$getent"

          mkdir -p "$bin"
          cp -a ${libc.bin}/. "$bin/"
          chmod -R u+w "$bin"

          AOS_RUNTIME_SHELL="${bash}/bin/bash" AOS_BUILD_SHELL="$CONFIG_SHELL" \
            "$CONFIG_SHELL" ${../../stdenv/runtime-scripts.sh} "$bin"

          # mtrace includes a Perl exec fallback as well as its shebang.
          sed -i \
            -e '1c#!${perl}/bin/perl' \
            -e 's|${buildPackages.perl}/bin/perl|${perl}/bin/perl|g' \
            "$bin/bin/mtrace"

          # glibc's output split moves pcprofiledump away from the configure
          # prefix recorded in xtrace. Keep that internal command in this output.
          sed -i "s|${libc}/bin/pcprofiledump|$bin/bin/pcprofiledump|g" \
            "$bin/bin/xtrace"

          for script in ldd sotruss xtrace; do
            test "$(head -n 1 "$bin/bin/$script")" = '#!${bash}/bin/bash'
          done
          test "$(head -n 1 "$bin/bin/mtrace")" = '#!${perl}/bin/perl'
        '';
      }
    ];

    meta = {
      description = "GNU libc utilities with target runtime interpreters";
      license = "LGPL-2.1-or-later";
      execute = {
        os = "linux";
        cpu = [stdenv.hostPlatform.constraints.cpu];
      };
    };
  }
