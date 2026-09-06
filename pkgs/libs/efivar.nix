##! efivar — EFI variable and device-path libraries
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  mandoc,
  popt,
}: let
  version = "39";
in
  mkDerivation {
    pname = "efivar";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/rhboot/efivar/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-ye3RXy7u6mMjLz5mmkjpkse+mv9X7iJnKsMfXsoWCaY=";
    };

    buildDeps = [gnumake pkg-config mandoc];
    runtimeDeps = [popt];
    propagatedDeps = [popt];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd efivar-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            PREFIX="$out" \
            LIBDIR="$out/lib" \
            BINDIR="$out/bin" \
            INCLUDEDIR="$out/include" \
            PCDIR="$out/lib/pkgconfig" \
            MANDOC="${mandoc}/bin/mandoc" \
            ENABLE_DOCS=1
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            PREFIX="$out" \
            LIBDIR="$out/lib" \
            BINDIR="$out/bin" \
            INCLUDEDIR="$out/include" \
            PCDIR="$out/lib/pkgconfig" \
            MANDIR="$out/share/man" \
            MANDOC="${mandoc}/bin/mandoc" \
            ENABLE_DOCS=1
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-efivar";
        library = self;
        libs = ["-lefivar"];
        testSource = ''
          #include <efivar/efivar.h>

          int main(void) {
              efi_guid_t guid;
              return efi_str_to_guid("8be4df61-93ca-11d2-aa0d-00e098032b8c", &guid) < 0;
          }
        '';
      };
    };

    meta = {
      description = "EFI variable and device-path libraries";
      homepage = "https://github.com/rhboot/efivar";
      license = "LGPL-2.1-only";
    };
  }
