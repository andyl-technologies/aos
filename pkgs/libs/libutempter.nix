##! libutempter — Pseudoterminal accounting helper library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.2.3";
in
  mkDerivation {
    pname = "libutempter";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/altlinux/libutempter/archive/refs/tags/${version}-alt1.tar.gz"];
      hash = "sha256-UoCcda+bDhMklSEXfe+FeH9FeIjLzuVRG/lv4G4UZxE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libutempter-${version}-alt1/libutempter
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's/-m2711/-m0711/' Makefile
          sed -i \
            's|LIBEXECDIR "/utempter/utempter"|"/run/wrappers/bin/utempter"|' \
            iface.c
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            libdir="$out/lib" \
            libexecdir="$out/libexec" \
            includedir="$out/include" \
            mandir="$out/share/man"
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            libdir="$out/lib" \
            libexecdir="$out/libexec" \
            includedir="$out/include" \
            mandir="$out/share/man"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libutempter";
        library = self;
        libs = ["-lutempter"];
        testSource = ''
          #include <utempter.h>

          int main(void) {
              utempter_set_helper(0);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "Interface for recording pseudoterminal sessions";
      homepage = "https://github.com/altlinux/libutempter";
      license = "LGPL-2.1-or-later";
    };
  }
