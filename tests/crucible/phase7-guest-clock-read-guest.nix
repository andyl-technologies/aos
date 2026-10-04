# A fresh Linux/x86 SDK workload, separate from the existing ownership guest.
{
  pkgs,
  source,
  cargoDeps,
}:
assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";
  pkgs.mkCargoPackage {
    pname = "crucible-guest-clock-read-initramfs";
    version = "0";
    src = source;
    inherit cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p crucible-guest --example crucible-guest-clock-read";
    cargoTestFlags = "-p crucible-guest --example crucible-guest-clock-read";
    installBins = false;
    buildDeps = [pkgs.patchelf pkgs.sqliteStatic pkgs.cpio pkgs.pigz];
    runtimeDeps = [];
    cargoEnv = {
      SQLITE3_LIB_DIR = "${pkgs.sqliteStatic}/lib";
      SQLITE3_INCLUDE_DIR = "${pkgs.sqliteStatic}/include";
      SQLITE3_STATIC = "1";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    };
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
      executable="''${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-gnu/release/examples/crucible-guest-clock-read"
      test -x "$executable"
      if patchelf --print-interpreter "$executable" > "$TMPDIR/clock-read.interpreter" 2>/dev/null; then
        echo "clock-read guest unexpectedly has an ELF interpreter" >&2
        exit 1
      fi
      mkdir -p "$TMPDIR/clock-read-root/proc" "$TMPDIR/clock-read-root/sys" "$TMPDIR/clock-read-root/dev"
      cp "$executable" "$TMPDIR/clock-read-root/init"
      chmod 0755 "$TMPDIR/clock-read-root/init"
      (
        cd "$TMPDIR/clock-read-root"
        find . -print0 | LC_ALL=C sort -z \
          | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
          | pigz -9 -n > "$out/initrd.img"
      )
      test -s "$out/initrd.img"
      cat > "$out/evidence.env" <<'EVIDENCE'
      guest_format=diskless-linux-initramfs
      guest_init=pid1-sdk-clock-read-equivalence
      guest_calls=clock_gettime-realtime,clock_gettime-monotonic,gettimeofday,rdtsc
      guest_read_boundary=typed-semantic-pre-post-markers
      guest_clock_read_batches=2
      guest_idle=original-linux-nanosleep-kernel-idle-wait
      guest_cpu_affinity=0
      EVIDENCE
    '';
  }
