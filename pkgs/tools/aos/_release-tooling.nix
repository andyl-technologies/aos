##! pkgs/tools/aos/_release-tooling.nix — The installed release tooling closure
#
# One store path holds the release coordinator CLI together with the native
# qualification executors it may drive. `aos maintain release` discovers both from
# this layout instead of reading store paths from the maintainer
# configuration (see crates/aos/src/commands/release/tooling.rs):
#
#   bin/{aos,apm,apr}                            wrappers exporting AOS_RELEASE_TOOLING
#   libexec/aos-release/executors/<platform>/run      qualification executor program
#   libexec/aos-release/executors/<platform>/identity identity the executor reports
#
# Every maintainer role on a machine (operator shell, coordinator, backup and
# restore checks) must run this same closure: its store path is the `tooling`
# fitness binding, so attestations recorded by one build never vouch for
# another.
{
  lib,
  runCommand,
  runtimeShell,
  aos,
  # Executors keyed by the platform they qualify. Each value is a
  # `mkQualificationExecutor` result; its `passthru.qualification.identity`
  # is the identity the coordinator pins for that platform.
  executors,
}: let
  platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

  # The wrapper names its own closure so the coordinator binds the tooling
  # path even when the CLI itself lives in a different store path.
  wrapper = name: program: ''
    cat > "$out/bin/${name}" <<WRAPPER
    #!${runtimeShell}
    export AOS_RELEASE_TOOLING="${placeholder "out"}"
    exec "${program}" "\$@"
    WRAPPER
    chmod 0555 "$out/bin/${name}"
  '';

  # The executor program is copied rather than linked: the coordinator
  # requires a regular file, as it does for the external signer.
  installExecutor = platform: executor: let
    identity = executor.passthru.qualification.identity;
  in
    assert builtins.elem platform platforms;
    assert executor.passthru.qualification.platform == platform;
    assert builtins.isString identity && identity != ""; ''
      directory="$out/libexec/aos-release/executors/${platform}"
      mkdir -p "$directory"
      cp "${lib.getExe executor}" "$directory/run"
      chmod 0555 "$directory/run"
      printf '%s\n' ${lib.escapeShellArg identity} > "$directory/identity"
    '';
in
  runCommand "aos-release-tooling-${aos.version}" {
    passthru = {
      inherit aos executors;
    };
  } (
    ''
      mkdir -p "$out/bin" "$out/libexec/aos-release/executors"
    ''
    + wrapper "aos" "${aos}/bin/aos"
    + wrapper "apm" "${aos.apm}/bin/apm"
    + wrapper "apr" "${aos.apr}/bin/apr"
    + lib.concatStrings (lib.mapAttrsToList installExecutor executors)
  )
