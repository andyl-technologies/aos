##! doxygen — Source documentation generator.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  perl,
  bash,
  bibtex,
  sqlite,
}: let
  version = "1.18.0";
  src = fetchurl {
    urls = ["https://github.com/doxygen/doxygen/releases/download/Release_1_18_0/doxygen-${version}.src.tar.gz"];
    hash = "0m6krlnqw731mr28cjnpm4iv5xy7km0rwaibbb4vwnvqlrqfvpm1";
  };
in
  mkDerivation {
    pname = "doxygen";
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.flex buildPackages.bison buildPackages.python3 buildPackages.libxml2];
    runtimeDeps = [perl bash bibtex sqlite];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd doxygen-${version}
            # Bootstrap GCC has no linker plugin. Doxygen forces IPO for
            # native release builds, so retain ordinary release codegen.
            sed -i 's/set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)/set(CMAKE_INTERPROCEDURAL_OPTIMIZATION FALSE)/' CMakeLists.txt
            # Citation processing invokes Perl through the portable shell
            # launcher; both executables must come from the AOS closure.
            sed -i 's|Portable::system("perl",|Portable::system("${perl}/bin/perl",|' src/cite.cpp
            sed -i 's|"/bin/sh"|"${bash}/bin/bash"|g' src/portable.cpp
            # List-form execution avoids an implicit host shell for BibTeX.
            sed -i 's|`bibtex $auxfile 2>\&1`|system("${bibtex}/bin/bibtex", $auxfile)|' templates/html/bib2xhtml.pl
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -Duse_sys_sqlite3=ON \
              -DCMAKE_PREFIX_PATH=${sqlite}
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              ctest --test-dir build --output-on-failure --parallel "$NIX_BUILD_CORES"
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/doxygen"
            cp LICENSE "$out/share/licenses/doxygen/"
            for license in deps/libmscgen/COPYING deps/spdlog/LICENSE \
              templates/html/MaterialSymbolsOutlined_LICENSE.txt
            do
              install -D -m644 "$license" "$out/share/licenses/doxygen/$license"
            done
          '';
        }
      ];

    meta = {
      description = "Documentation generator for source code";
      homepage = "https://www.doxygen.nl/";
      license = "GPL-2.0-or-later";
    };
  }
