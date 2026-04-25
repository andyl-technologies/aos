##! pigz — parallel gzip
##!
##! Drop-in replacement for gzip(1) that splits the input into 128 KiB
##! chunks and compresses them across N threads. Output is a standard
##! gzip stream, kernel- and gunzip-compatible. With `-n` the header
##! omits name + mtime, so the bytes are reproducible across runs and
##! across thread counts (pigz partitions the input deterministically;
##! threading only affects scheduling).
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "2.8";
in
  mkDerivation {
    pname = "pigz";
    inherit version;

    src = fetchurl {
      urls = [
        "https://zlib.net/pigz/pigz-${version}.tar.gz"
      ];
      hash = "sha256-64crTw4fDr5Zyfe9jFBsQgSJO6aoSS3jHfQW8NUXD9A=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pigz-${version}
        '';
      }
      {
        name = "build";
        # pigz has no ./configure; its Makefile picks up CC/CFLAGS/LDFLAGS
        # from the environment. The AOS ccWrapper already injects the
        # -isystem/-L/-Wl,-rpath flags for zlib, so a plain `make` links
        # correctly without further hints.
        script = ''
          make -j$NIX_BUILD_CORES CC="$CC"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/share/man/man1
          install -m 0755 pigz $out/bin/pigz
          ln -s pigz $out/bin/unpigz
          install -m 0644 pigz.1 $out/share/man/man1/pigz.1
        '';
      }
    ];

    meta = {
      description = "pigz — parallel implementation of gzip";
      homepage = "https://zlib.net/pigz/";
      license = "Zlib";
    };
  }
