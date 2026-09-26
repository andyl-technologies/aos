##! SWIG — Interface compiler for connecting native code to other languages
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  bison,
  gnumake,
  pcre2,
  perl,
  python3,
  tcl,
}: let
  version = "4.5.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "swig";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "SWIG emits a wrapper containing the function and module initialization symbols.";
        "files" = {
          "answer.i" = "%module answer\n%inline %{\nint answer(void) { return 42; }\n%}\n";
          "verify.py" = "content = open(\"answer_wrap.c\", encoding=\"utf-8\").read()\nrequired = [\"SWIG_init\",\"_wrap_answer\",\"return 42\"]\nassert all(fragment in content for fragment in required)\nprint(\"swig output passed\")\n";
        };
        "input" = "A SWIG interface exposing one inline C function to Python.";
        "operation" = "Generate the Python C wrapper and inspect its registration code.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/swig"
              "-python"
              "-o"
              "answer_wrap.c"
              "answer.i"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@python@"
              "verify.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "swig output passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "SWIG rejects the unterminated block with a syntax failure.";
        "files" = {
          "invalid.i" = "%module invalid\n%inline %{\nint answer(void) { return 42; }\n";
        };
        "input" = "A SWIG inline block with no closing delimiter.";
        "operation" = "Parse the unterminated interface definition.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/swig"
              "-python"
              "-o"
              "invalid_wrap.c"
              "invalid.i"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://github.com/swig/swig/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-3SGaDIlHr+Y7gYiSMEOQQnwu5/bt+ho3hT1O/YkZgr4=";
    };
    buildDeps = [autoconf automake libtool bison gnumake perl python3 tcl];
    runtimeDeps = [pcre2];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd swig-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          # CCache's optional manual requires Yodl, while all interface
          # compiler functionality and the main SWIG manual remain available.
          sed -i '/man1/d' CCache/Makefile.in
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" autogen.sh
        '';
      }
      {
        name = "configure";
        script = ''
          ./autogen.sh
          # PCRE2 is a runtime library, so its config script is not on PATH.
          PCRE2_CONFIG=${pcre2}/bin/pcre2-config \
            ./configure $configureFlags --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/swig" -version | grep -q 'SWIG Version ${version}'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-swig";
        tool = self;
        command = "swig -version | grep -q 'SWIG Version ${version}'";
      };
    };
    meta = {
      description = "Connects C and C++ code to high-level programming languages";
      homepage = "https://www.swig.org/";
      license = "GPL-3.0-or-later";
      mainProgram = "swig";
    };
  }
