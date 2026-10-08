##! pkgs/tools/aos/_release-tooling.nix — The installed release tooling closure
#
# One store path holds the release coordinator CLI together with the native
# qualification executors it may drive and the file-backed release signer.
# `aos maintain release` discovers all of them from this layout instead of
# reading store paths from the maintainer configuration (see
# crates/aos/src/commands/release/tooling.rs):
#
#   bin/{aos,apm,apr}                                 wrappers exporting AOS_RELEASE_TOOLING
#   bin/aos-release-signer                            link to the bundled signer, for operators
#   libexec/aos-release/executors/<platform>/run      qualification executor program
#   libexec/aos-release/executors/<platform>/identity identity the executor reports
#   libexec/aos-release/signer/aos-release-signer     bundled file-backed release signer
#
# Bundling the signer keeps its compiled-in registry allowlist in step with
# the coordinator's: both come from one source revision, so key custody holds
# only private keys and the signer configuration, never a signer binary.
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
  # The repository's file-backed `aos-release-signer` package.
  releaseSigner,
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

  # Executor and signer programs are copied rather than linked: the
  # coordinator requires a regular file, not a symbolic link.
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

  # The coordinator spawns this copy when the maintainer configuration names
  # no external signer executable. The `bin` link only gives operators the
  # same program for `aos-release-signer show`; the coordinator never uses it.
  installSigner = ''
    mkdir -p "$out/libexec/aos-release/signer"
    cp "${releaseSigner}/bin/aos-release-signer" "$out/libexec/aos-release/signer/aos-release-signer"
    chmod 0555 "$out/libexec/aos-release/signer/aos-release-signer"
    ln -s ../libexec/aos-release/signer/aos-release-signer "$out/bin/aos-release-signer"
  '';
in
  runCommand "aos-release-tooling-${aos.version}" {
    passthru = {
      inherit aos executors releaseSigner;
    };
  } (
    ''
      mkdir -p "$out/bin" "$out/libexec/aos-release/executors"
    ''
    + wrapper "aos" "${aos}/bin/aos"
    + wrapper "apm" "${aos.apm}/bin/apm"
    + wrapper "apr" "${aos.apr}/bin/apr"
    + lib.concatStrings (lib.mapAttrsToList installExecutor executors)
    + installSigner
  )
