##! smartypants Python module built from its source distribution.
{
  mkDerivation,
  fetchurl,
  python3,
  buildPackages,
}:
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
  pname = "python3-smartypants";
  version = "2.0.2";
  src = fetchurl {
    urls = ["https://files.pythonhosted.org/packages/6c/8f/a033f78196d9467b402d100ec40b95166d43fa2642693f23f771473d8195/smartypants-2.0.2.tar.gz"];
    hash = "39d64ce1d7cc6964b698297bdf391bc12c3251b7f608e6e55d857cd7c5f800c6";
  };
  buildDeps = [buildPackages.python3];
  runtimeDeps = [python3];
  propagatedDeps = [python3];
  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd smartypants-2.0.2
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/lib/python3.14/site-packages" "$out/share/licenses/python3-smartypants"
        cp -R smartypants.py "$out/lib/python3.14/site-packages/"
        cp COPYING "$out/share/licenses/python3-smartypants/"

            mkdir -p "$out/bin"
            cp smartypants "$out/bin/smartypants"
            sed -i '1c#!${python3}/bin/python3' "$out/bin/smartypants"
            sed -i '2iimport sys; sys.path.insert(0, "${builtins.placeholder "out"}/lib/python3.14/site-packages")' "$out/bin/smartypants"
            chmod +x "$out/bin/smartypants"

      '';
    }
  ];
  meta = {
    description = "smartypants Python module";
    homepage = "https://pypi.org/project/smartypants/";
    license = "BSD-3-Clause";
  };
}
