##! Graph layout engines and rendering tools.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  callPackage,
  stdenv,
  expat,
  zlib,
  libtool,
  cairo,
  pango,
  fontconfig,
  freetype,
  libpng,
  libwebp,
  harfbuzz,
}: let
  version = "16.1.0";
  glib = callPackage ../libs/_image-glib.nix {};
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "graphviz";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A directed graph containing source and target nodes.";
        operation = "Render the graph to SVG with the installed dot engine.";
        expected = "The SVG contains both node labels.";
        files."probe.dot" = "digraph probe { source -> target }\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/dot" "-Tsvg" "probe.dot" "-o" "probe.svg"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                svg = Path("probe.svg").read_text()
                assert "<svg" in svg
                assert "<title>source</title>" in svg
                assert "<title>target</title>" in svg
                print("graphviz rendered directed graph")
              ''
            ];
            exit_code = 0;
            stdout.exact = "graphviz rendered directed graph\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A directed graph with a missing edge target.";
        operation = "Parse the invalid DOT source.";
        expected = "Dot rejects the syntax error.";
        files."broken.dot" = "digraph probe { source -> }\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/dot" "-Tsvg" "broken.dot" "-o" "broken.svg"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/${version}/graphviz-${version}.tar.xz"];
      hash = "1hw32zvc47gzk9wq0h0gnxnx41b6cjmm7yyhpb1qs9p5ycc1frhg";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config buildPackages.flex buildPackages.bison buildPackages.python3];
    runtimeDeps = [expat zlib libtool cairo pango fontconfig freetype libpng libwebp glib harfbuzz];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd graphviz-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            # Pango uses the image stack's GLib, including its development output.
            export PKG_CONFIG_PATH="${glib.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${glib.dev}/lib $NIX_LDFLAGS ''${LDFLAGS:-}"
            ${
              if stdenv.isCross && stdenv.hostPlatform.isLinux
              then ''
                # The cross linker does not search build-tree RUNPATH entries
                # when resolving indirect dependencies of Graphviz's shared libs.
                for library in cdt cgraph gvc pathplan xdot; do
                  export LDFLAGS="$LDFLAGS -Wl,-rpath-link,$PWD/lib/$library/.libs"
                done
              ''
              else ""
            }
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
          '';
        }
        {
          name = "install";
          script = ''
            make install SHELL="$CONFIG_SHELL"
            mkdir -p "$out/share/licenses/graphviz"
            cp COPYING cpl1.0.txt "$out/share/licenses/graphviz/"
            ${
              if stdenv.isCross && stdenv.hostPlatform.isLinux
              then ''
                # Plugin registrations contain names and format capabilities, not
                # machine addresses. Reuse the matching native Linux inventory
                # only when both builds install exactly the same plugin libraries.
                find "$out/lib/graphviz" -name 'libgvplugin_*.so.8' -printf '%f\n' | sort > target-plugins
                find ${buildPackages.graphviz}/lib/graphviz -name 'libgvplugin_*.so.8' -printf '%f\n' | sort > native-plugins
                cmp target-plugins native-plugins
                cp ${buildPackages.graphviz}/lib/graphviz/config8 "$out/lib/graphviz/config8"
              ''
              else ""
            }
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
              "$out/bin/dot" -c
              printf '%s\n' 'digraph { source -> staging }' > smoke.dot
              "$out/bin/dot" -Tsvg smoke.dot -o smoke.svg
              grep -q '<svg' smoke.svg
              grep -q 'source' smoke.svg
              grep -q 'staging' smoke.svg
              # Loading installed plugins exercises their runtime library paths.
              "$out/bin/dot" -Tpng:cairo smoke.dot -o smoke.png
              "$out/bin/dot" -Twebp smoke.dot -o smoke.webp
              test -s smoke.png
              test -s smoke.webp
            '';
          }
        ]
      );

    meta = {
      description = "Graph layout engines and rendering tools";
      homepage = "https://graphviz.org/";
      license = "EPL-2.0";
    };
  }
