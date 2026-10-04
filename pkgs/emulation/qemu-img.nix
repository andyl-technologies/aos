##! qemu-img — standalone QEMU disk image utility
{
  lib,
  mkDerivation,
  stdenv,
  buildPackages,
  qemu,
  glib,
  zlib,
  zstd,
  libgcrypt,
  gnutls,
  gcc-libs,
  bzip2,
}: let
  version = qemu.version;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  darwinSigner =
    if isDarwinCross
    then
      import ./_darwin-signer.nix {
        inherit (buildPackages) mkDerivation fetchurl gnumake pkg-config openssl;
      }
    else null;

  # Libraries the copied utility links. Its crypto backends follow QEMU's
  # platform configuration.
  runtimeLibraries =
    [glib zlib zstd]
    ++ lib.optionals (!isDarwinCross) [libgcrypt gnutls]
    ++ lib.optionals stdenv.hostPlatform.isLinux [gcc-libs bzip2];
in
  mkDerivation {
    pname = "qemu-img";
    inherit version;
    src = null;

    # qemu is only the source of the already-built utility. The scrub phase
    # removes its compiled-in installation prefix so this small runtime tool
    # does not retain the complete system emulator.
    # The install script references the already-built target artifact directly.
    # Do not splice QEMU into the native tool role for cross builds.
    buildDeps =
      lib.optional (!stdenv.isCross) qemu
      ++ lib.optional isDarwinCross darwinSigner;
    # Preserve every library linked by the copied utility during reference
    # scrubbing.
    runtimeDeps = runtimeLibraries;
    propagatedDeps = [];
    disallowedReferences = [qemu];
    # The source utility is already stripped. Darwin's copied binary must be
    # scrubbed and re-signed in that order, so skip the later generic passes.
    dontStrip = lib.optionalString isDarwinCross "1";
    dontNukeRefs = lib.optionalString isDarwinCross "1";

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp ${qemu}/bin/qemu-img "$out/bin/qemu-img"
          ${lib.optionalString (!isDarwinCross) ''
            # QEMU's fixup already shrank this binary's RUNPATH, and patchelf
            # leaves the dead tail of the original string in .dynstr. That tail
            # names every library directory QEMU linked against, including
            # inputs this utility never loads. Keep only the live RUNPATH,
            # the interpreter, and the declared runtime libraries; the generic
            # scrub would also keep transitively propagated inputs.
            chmod u+w "$out/bin/qemu-img"
            keep_roots="$out ${lib.concatStringsSep " " runtimeLibraries}"
            for dir in $(patchelf --print-rpath "$out/bin/qemu-img" | tr ':' ' ') \
                $(patchelf --print-interpreter "$out/bin/qemu-img"); do
              keep_roots="$keep_roots $dir"
            done
            keep=$(printf '%s\n' $keep_roots \
              | sed -n 's|^${builtins.storeDir}/\([0-9a-z]\{32\}\)-.*|\1|p' \
              | sort -u | paste -sd '|')

            # patchelf's blanking can cut the "/nix/" prefix off the dead
            # tail, which nuke-refs requires, so match on "store/<hash>-".
            LC_ALL=C awk -v keep="$keep" '
              BEGIN { dummy = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }
              {
                out = ""
                s = $0
                while (match(s, /store\/[0-9a-z]{32}-/)) {
                  hash = substr(s, RSTART + 6, 32)
                  if (hash ~ ("^(" keep ")$")) {
                    out = out substr(s, 1, RSTART + RLENGTH - 1)
                  } else {
                    out = out substr(s, 1, RSTART + 5) dummy "-"
                  }
                  s = substr(s, RSTART + RLENGTH)
                }
                print out s
              }
            ' "$out/bin/qemu-img" > qemu-img.scrubbed
            chmod --reference="$out/bin/qemu-img" qemu-img.scrubbed
            mv qemu-img.scrubbed "$out/bin/qemu-img"
          ''}
          ${lib.optionalString isDarwinCross ''
            nuke-refs \
              -e "$out" \
              -e ${glib} \
              -e ${zlib} \
              -e ${zstd} \
              "$out/bin/qemu-img"
            ldid -S "$out/bin/qemu-img"
            ldid -e "$out/bin/qemu-img" >/dev/null
          ''}
        '';
      }
    ];

    passthru.evidenceSources = [qemu.src];

    meta = {
      description = "QEMU disk image utility without the system emulators";
      homepage = "https://www.qemu.org";
      license = "GPL-2.0-only";
    };
  }
