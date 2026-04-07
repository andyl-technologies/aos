# stdenv/toolchains/gcc11/linux-headers.nix — Linux 5.14 headers (RHEL 9)
#
# Kernel headers installed via headers_install. Required by glibc 2.34.
#
{
  prev,
  gcc,
  binutils,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.14.tar.xz";
    hash = "15c91flxhankd62xwv02azjxy4hqll4s3jsl5kq8vbhjrz57lcl0";
  };
in
builtins.derivation {
  name = "linux-headers-5.14";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"

      # Linux 5.3+ uses rsync for headers_install. Provide a minimal replacement.
      mkdir -p "$TMPDIR/fakebin"
      cat > "$TMPDIR/fakebin/rsync" << 'RSYNC_EOF'
#!/bin/sh
# Minimal rsync replacement for kernel headers_install.
# Handles: rsync -mrl --include='*.h' --exclude='*' src/ dst/
shift_flags() { while [ $# -gt 0 ]; do case "$1" in -*) shift ;; *) break ;; esac; done; echo "$@"; }
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
      mkdir linux-5.14 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd linux-5.14 && ${prev.tar}/bin/tar xf -)
      cd linux-5.14
      chmod -R u+w .

      make ARCH=${hostPlatform.linuxArch} INSTALL_HDR_PATH="$out" headers_install

      echo "Linux 5.14 headers installed to $out"
    ''
  ];
}
// {
  meta = {
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
