# Shared static Linux SDK initramfs construction for focused guest fixtures.
{
  pkgs,
  source,
  cargoDeps,
  pname,
  example,
  rootName,
  cargoEnv ? {},
  extraPackages ? [],
  extraFiles ? {},
  # The literal includes its final newline, keeping the heredoc byte-preserved.
  evidence,
}:
assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";
  pkgs.mkCargoPackage {
    inherit pname;
    version = "0";
    src = source;
    inherit cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p crucible-guest --example ${example}";
    cargoTestFlags = "-p crucible-guest --example ${example}";
    installBins = false;
    buildDeps = [pkgs.patchelf pkgs.sqliteStatic pkgs.cpio pkgs.pigz] ++ extraPackages;
    runtimeDeps = [];
    cargoEnv =
      {
        SQLITE3_LIB_DIR = "${pkgs.sqliteStatic}/lib";
        SQLITE3_INCLUDE_DIR = "${pkgs.sqliteStatic}/include";
        SQLITE3_STATIC = "1";
        LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      }
      // cargoEnv;
    preBuild = ''
      # Keep the established static guest contract: host proc macros remain
      # dynamic, while the explicit target executable has no ELF interpreter.
      target_triple="$(rustc -vV | sed -n 's/^host: //p')"
      test "$target_triple" = x86_64-unknown-linux-gnu
      mkdir -p "$TMPDIR/static-shim"
      ln -s "$(dirname "$(cc -print-libgcc-file-name)")/libgcc_s.a" \
        "$TMPDIR/static-shim/libgcc_eh.a"
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static -L $TMPDIR/static-shim"
      export CARGO_BUILD_TARGET="$target_triple"
    '';
    postInstall = ''
      set -eu
      executable="''${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-gnu/release/examples/${example}"
      test -x "$executable"
      if patchelf --print-interpreter "$executable" > "$TMPDIR/${rootName}.interpreter" 2>/dev/null; then
        echo "${rootName} guest unexpectedly has an ELF interpreter" >&2
        exit 1
      fi
      mkdir -p "$TMPDIR/${rootName}-root/proc" "$TMPDIR/${rootName}-root/sys" "$TMPDIR/${rootName}-root/dev"
      cp "$executable" "$TMPDIR/${rootName}-root/init"
      chmod 0755 "$TMPDIR/${rootName}-root/init"${
        if extraFiles == {}
        then ""
        else
          "\n"
          + builtins.concatStringsSep "\n" (map (name: ''
            cp ${extraFiles.${name}} "$TMPDIR/${rootName}-root/${name}"
          '') (builtins.attrNames extraFiles))
      }
      (
        cd "$TMPDIR/${rootName}-root"
        find . -print0 | LC_ALL=C sort -z \
          | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
          | pigz -9 -n > "$out/initrd.img"
      )
      test -s "$out/initrd.img"
      cat > "$out/evidence.env" <<'EVIDENCE'
      ${evidence}EVIDENCE
    '';
  }
