##! python3-railroad-diagrams — Railroad syntax diagrams for Python
{
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
}:
mkDerivation {
  pname = "python3-railroad-diagrams";
  version = "3.0.1";

  src = fetchurl {
    urls = [
      "https://files.pythonhosted.org/packages/3a/08/25c49a573ff9c482cc7bc48574440170a6a9ad5562de5c50db8887ecfece/railroad-diagrams-3.0.1.tar.gz"
    ];
    hash = "a91332bac900cb3c367331fa9b699f0897bcf86b7264f65458675df430d04ce3";
  };

  buildDeps = [buildPackages.python3];
  runtimeDeps = [python3];
  propagatedDeps = [python3];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd railroad-diagrams-3.0.1
      '';
    }
    {
      name = "install";
      script = ''
        site="$out/lib/python3.14/site-packages"
        metadata="$site/railroad_diagrams-3.0.1.dist-info"
        mkdir -p "$metadata" "$out/share/licenses/python3-railroad-diagrams"
        cp railroad.py "$site/"
        cp PKG-INFO "$metadata/METADATA"
        cp LICENSE "$metadata/LICENSE"
        cp LICENSE "$out/share/licenses/python3-railroad-diagrams/"

        PYTHONPATH="$site" ${buildPackages.python3}/bin/python3 - <<'PYTHON'
        import io
        import railroad

        output = io.StringIO()
        railroad.Diagram(railroad.Terminal("token")).writeSvg(output.write)
        assert "<svg" in output.getvalue()
        PYTHON
      '';
    }
  ];

  meta = {
    description = "Railroad syntax diagram generator for Python";
    homepage = "https://github.com/tabatkins/railroad-diagrams";
    license = "MIT";
  };
}
