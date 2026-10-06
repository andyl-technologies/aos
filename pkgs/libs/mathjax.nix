##! Uncompressed MathJax JavaScript sources for offline formula rendering
{
  mkDerivation,
  fetchurl,
}: let
  version = "2.7.9";
in
  mkDerivation {
    pname = "mathjax";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/mathjax/MathJax/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-yRZyech9oETy/5EK1XOgLOkDVMtZRArlaOuG4WMPZd8=";
    };

    buildDeps = [];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd MathJax-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/mathjax" "$out/share/licenses/mathjax"
          # Execute the original JavaScript sources, including SVG glyph
          # definitions, without an upstream minified bundle or CDN fetch.
          cp -R unpacked/. "$out/share/mathjax/"
          cp -R fonts "$out/share/mathjax/"
          cp LICENSE "$out/share/licenses/mathjax/"
        '';
      }
    ];

    meta = {
      description = "Uncompressed MathJax JavaScript for offline mathematics rendering";
      homepage = "https://www.mathjax.org/";
      license = "Apache-2.0 AND OFL-1.1 AND LPPL-1.3c";
    };
  }
