{mkDerivation, fetchurl, m4, flex, bison, autoconf, automake, texinfo, gnumake, bash, gzip, bzip2, xz, zstd}:
let
  version = "1.35";
in
  mkDerivation {
    pname = "tar";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/tar/tar-${version}.tar.xz"];
      hash = "05nw7q7sazkana11hnf3f77lmybw1j9j6lsk93bsxirf6hvzyqjd";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [bash gzip bzip2 xz zstd];
    configureFlags = "--disable-nls";
    postInstall = ''
      find "$out" -type f -perm -u+x | while read f; do
        [ "$(head -c 2 "$f" 2>/dev/null)" = "#!" ] || continue
        sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
      done
    '';

    meta = {
      description = "GNU tar archiving utility";
      homepage = "https://www.gnu.org/software/tar/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
