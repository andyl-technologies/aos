##! esbuild — JavaScript and CSS bundler built from upstream Go sources.
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "0.28.1";
  src = fetchurl {
    urls = [
      "https://github.com/evanw/esbuild/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-ZcdW+ofUMXisSlJCRUwr0P3jJfjs93mX+PpLiPlNXNI=";
  };
in
  mkGoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "esbuild";
    inherit version src;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A JavaScript module that prints a fixed value.";
        operation = "Bundle the module into a single output file.";
        expected = "The bundle retains the logging call and its value.";
        files."input.js" = "console.log(42);\n";
        steps = [
          {
            argv = ["@out@/bin/esbuild" "input.js" "--bundle" "--log-level=error" "--outfile=bundle.js"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" "from pathlib import Path; content = Path('bundle.js').read_text(); assert 'console.log(42)' in content; print('bundle passed')"];
            exit_code = 0;
            stdout.exact = "bundle passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A JavaScript module with an incomplete initializer.";
        operation = "Ask esbuild to bundle the malformed module.";
        expected = "Esbuild rejects the syntax error.";
        files."invalid.js" = "const answer = ;\n";
        steps = [
          {
            argv = ["@out@/bin/esbuild" "invalid.js" "--bundle" "--log-level=error" "--outfile=invalid-bundle.js"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
        artifacts = [];
      };
    };
    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-S2uhvYBwdLq6KEv59RmLqLgosbGxK1A6hMaVu6qnnfI=";
    };
    goPackage = "./cmd/esbuild";
    goOutput = "esbuild";
    doCheck = false;
    runtimeDeps = [];
    meta = {
      description = "JavaScript and CSS bundler built from source";
      homepage = "https://esbuild.github.io/";
      license = "MIT";
    };
  }
