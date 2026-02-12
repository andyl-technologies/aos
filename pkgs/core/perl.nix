# Perl — Practical Extraction and Reporting Language
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "perl-${versions.core.perl}";
  version = versions.core.perl;

  src = fetchurl {
    inherit (sources.perl) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd perl-${versions.core.perl}
      '';
    }
    { name = "configure";
      script = ''
        ./Configure \
          -des \
          -Dprefix=$out \
          -Dvendorprefix=$out \
          -Dprivlib=$out/lib/perl5/${versions.core.perl} \
          -Darchlib=$out/lib/perl5/${versions.core.perl}/x86_64-linux \
          -Dvendorlib=$out/lib/perl5/${versions.core.perl} \
          -Dvendorarch=$out/lib/perl5/${versions.core.perl}/x86_64-linux \
          -Dman1dir=$out/share/man/man1 \
          -Dman3dir=$out/share/man/man3 \
          -Dusethreads \
          -Duseshrplib
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
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
