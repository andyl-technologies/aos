##! Reading and writing DWARF debugging information.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  python3,
  xz,
  zlib,
  zstd,
}: let
  version = "0.9.2";
  consumerSource = ''
    #include <cstdio>
    #include <dwarf.h>
    #include <libdwarf.h>

    int main(int argc, char** argv) {
        const bool reject = argc > 1;
        Dwarf_Debug debug = nullptr;
        Dwarf_Error error = nullptr;
        const int result = dwarf_init_path(reject ? "consumer.cc" : argv[0],
            nullptr, 0, DW_GROUPNUMBER_ANY, nullptr, nullptr, &debug, &error);
        if (reject) {
            if (error) dwarf_dealloc_error(debug, error);
            if (result == DW_DLV_OK) {
                dwarf_finish(debug);
                return 2;
            }
            std::fputs("libdwarf rejected invalid input\n", stderr);
            return 7;
        }
        if (result != DW_DLV_OK || dwarf_finish(debug) != DW_DLV_OK) return 2;
        return std::puts("libdwarf api passed") == EOF;
    }
  '';
  probe = reject: {
    input =
      if reject
      then "A source text file rather than a binary object."
      else "The debug-enabled ELF consumer executable.";
    operation =
      if reject
      then "Confirm dwarf_init_path refuses the source file."
      else "Open the executable as a DWARF object and release its debug context.";
    expected =
      if reject
      then "The library rejects the invalid input."
      else "The public API returns the expected value.";
    files."consumer.cc" = consumerSource;
    artifacts = [];
    steps = [
      {
        argv =
          ["@cxx@" "consumer.cc" "-std=c++20" "-g" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"]
          ++ ["-ldwarf"]
          ++ ["-o" "consumer"];
        exit_code = 0;
        stdout.exact = "";
      }
      ({
          argv =
            [
              "@work@/${
                if reject
                then "bad-input"
                else "primary"
              }/consumer"
            ]
            ++ (
              if reject
              then ["reject"]
              else []
            );
          exit_code =
            if reject
            then 7
            else 0;
          observes_rejection = reject;
          stdout.exact =
            if reject
            then ""
            else "libdwarf api passed\n";
        }
        // (
          if reject
          then {stderr.exact = "libdwarf rejected invalid input\n";}
          else {}
        ))
    ];
  };
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "libdwarf";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = probe false;
      badInput = probe true;
    };
    version = "=${version}";

    src = fetchurl {
      urls = ["https://www.prevanders.net/libdwarf-${version}.tar.xz"];
      hash = "sha256-IrZtBoMadvagYhJs3K0/zFhUC4mhrLI8mfiGH1CZnsM=";
    };

    buildDeps = [cmake gnumake xz python3];
    runtimeDeps = [zlib zstd];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libdwarf-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_PREFIX_PATH="${zlib};${zstd}" \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED=ON \
            -DBUILD_NON_SHARED=ON \
            -DBUILD_DWARFDUMP=ON \
            -DDO_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir build --output-on-failure
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p $out/share/licenses/libdwarf
          cp COPYING AUTHORS $out/share/licenses/libdwarf/
          cp src/lib/libdwarf/LGPL.txt src/lib/libdwarf/LIBDWARFCOPYRIGHT \
            src/bin/dwarfdump/GPL.txt src/bin/dwarfdump/DWARFDUMPCOPYRIGHT \
            $out/share/licenses/libdwarf/

          # BSD contributors place their binary-distribution notices in source
          # comments. Preserve each notice verbatim alongside the component texts.
          python3 - "$out/share/licenses/libdwarf/BSD-NOTICES.txt" <<'PY'
          import pathlib
          import re
          import sys

          notices = []
          for directory in ("src/lib", "src/bin/dwarfdump"):
              for source in sorted(pathlib.Path(directory).rglob("*")):
                  if not source.is_file() or source.suffix not in (".c", ".h"):
                      continue

                  for comment in re.findall(r"/\*.*?\*/", source.read_text(), re.DOTALL):
                      words = comment.lower()
                      if "copyright" in words and "redistribution" in words:
                          notices.append(f"{source}\n{comment}\n")

          if not notices:
              raise SystemExit("libdwarf BSD notices were not found")

          pathlib.Path(sys.argv[1]).write_text("\n".join(notices))
          PY
        '';
      }
    ];

    meta = {
      description = "DWARF debugging information reader and writer";
      homepage = "https://www.prevanders.net/dwarf.html";
      license = "LGPL-2.1-only AND GPL-2.0-only AND BSD-2-Clause AND BSD-3-Clause";
    };
  }
