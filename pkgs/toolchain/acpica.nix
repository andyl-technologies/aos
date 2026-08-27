##! acpica — ACPICA user-space tools (iasl ACPI source-language compiler)
##!
##! Built for the `iasl` compiler that EDK2's OVMF build invokes to
##! compile `.asl`/`.dsl` ACPI table sources. The upstream unix
##! makefiles drive the build; only `iasl` is built and installed.
{
  mkDerivation,
  fetchurl,
  gnumake,
  flex,
  bison,
  m4,
  stdenv,
}: let
  version = "R2025_04_04";
in
  mkDerivation {
    pname = "acpica";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/acpica/acpica/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-mZHsEDs2YNF3FXgEBu50CfcFz4esVemjI3Sv/hpvJ1o=";
    };

    buildDeps = [
      gnumake
      flex
      bison
      m4
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd acpica-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES iasl \
            ${
            if stdenv.hostPlatform.isDarwin
            then "ACPI_HOST=_APPLE"
            else ""
          } \
            YACC=bison \
            LEX=flex \
            NOWERROR=TRUE \
            NOFORTIFY=TRUE
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp generate/unix/bin/iasl $out/bin/
        '';
      }
    ];

    meta = {
      description = "acpica — ACPI source-language compiler (iasl)";
      homepage = "https://www.acpica.org/";
      license = "Intel-ACPI OR GPL-2.0-only OR BSD-3-Clause";
    };
  }
