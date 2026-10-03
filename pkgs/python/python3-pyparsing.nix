##! python3-pyparsing — Declarative text parsers and syntax diagrams
{
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
  python3-jinja2,
  python3-railroad-diagrams,
}:
mkDerivation {
  pname = "python3-pyparsing";
  version = "3.3.3";

  src = fetchurl {
    urls = [
      "https://files.pythonhosted.org/packages/e4/11/b213bebff182584360cb8d17c72c1677fec5c5c228de439e63bcf8ab1c8f/pyparsing-3.3.3.tar.gz"
    ];
    hash = "928ae7e20211f3b6f3915a72f06a0cfd29ab9d24279dd6346b6b1a7146397d36";
  };

  buildDeps = [
    buildPackages.python3
    buildPackages.python3-jinja2
    buildPackages.python3-markupsafe
    buildPackages.python3-railroad-diagrams
  ];
  runtimeDeps = [python3 python3-jinja2 python3-railroad-diagrams];
  propagatedDeps = [python3 python3-jinja2 python3-railroad-diagrams];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd pyparsing-3.3.3
      '';
    }
    {
      name = "check";
      script = ''
        ${buildPackages.python3}/bin/python3 -m unittest tests.test_simple_unit
      '';
    }
    {
      name = "install";
      script = ''
        site="$out/lib/python3.14/site-packages"
        metadata="$site/pyparsing-3.3.3.dist-info"
        mkdir -p "$metadata" "$out/share/licenses/python3-pyparsing"
        cp -R pyparsing "$site/"
        cp PKG-INFO "$metadata/METADATA"
        cp LICENSE "$metadata/LICENSE"
        cp LICENSE "$out/share/licenses/python3-pyparsing/"

        # Preserve the optional diagram API and its actual dependencies rather
        # than packaging only the parser subset used by a particular generator.
        PYTHONPATH="$site:${buildPackages.python3-jinja2}/lib/python3.14/site-packages:${buildPackages.python3-markupsafe}/lib/python3.14/site-packages:${buildPackages.python3-railroad-diagrams}/lib/python3.14/site-packages" \
          ${buildPackages.python3}/bin/python3 -P - <<'PYTHON'
        import importlib.metadata
        import pyparsing
        import pyparsing.diagram

        assert importlib.metadata.version("pyparsing") == "3.3.3"
        assert pyparsing.Word(pyparsing.alphas).parse_string("token")[0] == "token"
        PYTHON
      '';
    }
  ];

  meta = {
    description = "Declarative text parsing and railroad syntax diagrams";
    homepage = "https://github.com/pyparsing/pyparsing";
    license = "MIT";
  };
}
