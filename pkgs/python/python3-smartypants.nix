##! smartypants Python module built from its source distribution.
{
  lib,
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
  qualification.packageProbe = lib.qualification.commandProbe {
    primary = {
      input = "Quoted text with a double hyphen.";
      operation = "Transform the text through the installed smartypants module.";
      expected = "Quotes and the dash become typographic HTML entities.";
      files = {};
      artifacts = [];
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              from smartypants import smartypants

              assert smartypants('"Hello" -- AOS') == "&#8220;Hello&#8221; &#8212; AOS"
              print("smartypants typography passed")
            ''
          ];
          exit_code = 0;
          stdout.exact = "smartypants typography passed\n";
          stderr.exact = "";
        }
        {
          argv = ["@out@/bin/smartypants"];
          stdin = "\"Hello\" -- AOS\n";
          exit_code = 0;
          stdout.exact = "&#8220;Hello&#8221; &#8212; AOS\n";
          stderr.exact = "";
        }
      ];
    };
    badInput = {
      input = "A non-text value.";
      operation = "Pass the value to the installed smartypants module.";
      expected = "The module rejects it with TypeError.";
      files = {};
      artifacts = [];
      steps = [
        {
          argv = [
            "@python@"
            "-c"
            ''
              from smartypants import smartypants

              try:
                  smartypants(None)
              except TypeError:
                  print("smartypants rejected non-text input")
              else:
                  raise SystemExit(1)
            ''
          ];
          exit_code = 0;
          observes_rejection = true;
          stdout.exact = "smartypants rejected non-text input\n";
          stderr.exact = "";
        }
      ];
    };
  };
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
            sed -i '/^import sys$/a sys.path.insert(0, "${builtins.placeholder "out"}/lib/python3.14/site-packages")' "$out/bin/smartypants"
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
