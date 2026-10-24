# A private ABI-probe tool built entirely by the completed predecessor tier.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  lib = import ../../../lib {
    system = buildPlatform.system;
    bash = prev.bash;
  };
  tierStdenv =
    (import ../../tier-stdenv.nix {
      inherit lib buildPlatform hostPlatform targetPlatform;
    }) {
      tc = prev;
      staticDefault = true;
      staticNoPie = true;
    };
  fileSource = builtins.derivation {
    name = "file-5.48.tar.gz";
    system = buildPlatform.system;
    builder = "builtin:fetchurl";
    url = "https://astron.com/pub/file/file-5.48.tar.gz";
    outputHash = "sha256-7RRlaIOyOjZLQFfAVZXZMlLam8Rz0wEGUZUZ0NoUEoM=";
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
  };
in
  tierStdenv.mkDerivation {
    pname = "file";
    version = "5.48";
    name = "gcc-unwind-context-file-5.48";
    src = fileSource;
    buildDeps = [prev.gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    passthru.evidenceSources = [./unwind-file.nix fileSource ../../runtime-scripts.sh];
    phases = [
      {
        name = "unpack";
        script = ''
          ${prev.tar}/bin/tar --no-same-owner -xf "$src"
          cd file-5.48
          AOS_RUNTIME_SHELL="$CONFIG_SHELL" "$CONFIG_SHELL" ${../../runtime-scripts.sh} .
        '';
      }
      {
        name = "build";
        script = ''
          # No optional upstream capability is disabled for this private tool.
          "$CONFIG_SHELL" ./configure --prefix="$out" \
            --build=${buildPlatform.config} --host=${hostPlatform.config} \
            --target=${hostPlatform.config} \
            --enable-static
          # The predecessor wrapper produces static executables. Tell libtool
          # about that policy for file and its test, while retaining both
          # shared and static libmagic builds and every upstream capability.
          make SHELL="$CONFIG_SHELL" \
            'file_LDADD=libmagic.la -lm -all-static' \
            'test_LDADD=$(top_builddir)/src/libmagic.la -all-static' \
            -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          make SHELL="$CONFIG_SHELL" \
            'file_LDADD=libmagic.la -lm -all-static' \
            'test_LDADD=$(top_builddir)/src/libmagic.la -all-static' \
            check
        '';
      }
      {
        name = "install";
        script = ''
          make SHELL="$CONFIG_SHELL" \
            'file_LDADD=libmagic.la -lm -all-static' \
            'test_LDADD=$(top_builddir)/src/libmagic.la -all-static' \
            install
          test -f "$out/lib/libmagic.a"
          test -f "$out/lib/libmagic.so"
          printf 'AOS context ABI probe\n' > "$TMPDIR/file-probe.txt"
          test "$("$out/bin/file" --brief "$TMPDIR/file-probe.txt")" = 'ASCII text'
        '';
      }
    ];
    meta = {
      description = "Predecessor-built file helper for GNU context ABI probes";
      homepage = "https://darwinsys.com/file/";
      license = "BSD-2-Clause";
    };
  }
