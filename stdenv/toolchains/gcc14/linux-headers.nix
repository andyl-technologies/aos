# stdenv/toolchains/gcc14/linux-headers.nix — Linux 6.12 headers (RHEL 10)
#
# Kernel headers installed via headers_install. Required by glibc 2.39.
#
{
  prev,
  gcc,
  binutils,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    # Canonical kernel.org CDN: builtins.fetchTarball takes a single
    # URL with no fallback, and independent mirrors prune old
    # releases from v6.x (csclub.uwaterloo.ca dropped 6.12 and began
    # returning 404 for this pin), while kernel.org retains every
    # release permanently. Same bytes, so the unpacked-tree hash pin
    # is unchanged.
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.tar.xz";
    sha256 = "1dnxa60qxkjb8yqadbb1aglj8p57pqkmmg8ikdmlqxlb4vh7vnz3";
  };
in
  builtins.derivation {
    name = "linux-headers-6.12";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
              set -eu
              export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

              # GCC 14 defaults to PIE, but Scrt1.o isn't in the specs dir.
              # Wrap gcc to disable PIE for the kernel host tools (fixdep etc.).
              # -idirafter supplies stdio.h etc.: gccRaw's specs file no longer
              # embeds the prev.glibc/prev.linuxHeaders include paths (scrubbed to
              # keep gccRaw's $out free of the pre-tier chain), so this build must
              # supply them itself at build time.
              mkdir -p "$TMPDIR/fakebin"
              printf '#!/bin/sh\nexec ${gcc}/bin/gcc -static -no-pie -L${prev.glibc}/lib -idirafter ${prev.glibc}/include -idirafter ${prev.linuxHeaders} "$@"\n' > "$TMPDIR/fakebin/gcc"
              chmod +x "$TMPDIR/fakebin/gcc"

              # Linux 5.3+ uses rsync for headers_install. Provide a minimal replacement.
              cat > "$TMPDIR/fakebin/rsync" << 'RSYNC_EOF'
        #!/bin/sh
        # Minimal rsync replacement for kernel headers_install.
        # Handles: rsync -mrl --include='*.h' --exclude='*' src/ dst/
        src="" dst=""
        for arg; do
          case "$arg" in -*) ;; *) if [ -z "$src" ]; then src="$arg"; else dst="$arg"; fi ;; esac
        done
        if [ -d "$src" ]; then
          cd "$src"
          find . -name '*.h' | while read f; do
            d="$(dirname "$f")"
            mkdir -p "$dst/$d"
            cp "$f" "$dst/$d/"
          done
        fi
        RSYNC_EOF
              chmod +x "$TMPDIR/fakebin/rsync"
              export PATH="$TMPDIR/fakebin:$PATH"

              cd "$TMPDIR"
              mkdir linux-6.12 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd linux-6.12 && ${prev.tar}/bin/tar xf -)
              cd linux-6.12
              chmod -R u+w .

              make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

              echo "Linux 6.12 headers installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "Linux 6.12 kernel headers";
      homepage = "https://www.kernel.org/";
      license = "GPL-2.0-only";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
