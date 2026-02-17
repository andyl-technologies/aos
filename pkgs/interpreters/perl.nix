##! Perl — Practical Extraction and Reporting Language
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "5.40.1";
in
  mkDerivation {
    pname = "perl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.cpan.org/src/5.0/perl-${version}.tar.xz"
      ];
      hash = "sha256-36IMLu8rSvEzUlYQu7Zd0Td37PmYycWxzPDTCOcy7j8=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd perl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./Configure \
            -des \
            -Dprefix=$out \
            -Dvendorprefix=$out \
            -Dprivlib=$out/lib/perl5/${version} \
            -Darchlib=$out/lib/perl5/${version}/x86_64-linux \
            -Dvendorlib=$out/lib/perl5/${version} \
            -Dvendorarch=$out/lib/perl5/${version}/x86_64-linux \
            -Dman1dir=$out/share/man/man1 \
            -Dman3dir=$out/share/man/man3 \
            -Dusethreads \
            -Duseshrplib
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "Perl — practical extraction and reporting language";
      homepage = "https://www.perl.org";
      license = "Artistic-1.0-Perl";
    };
  }
