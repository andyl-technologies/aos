##! Exercises additional Q-through-Z source generators through emitted code.
{testing}: let
  verificationProgram = {
    path,
    requiredFragments,
    success,
  }: ''
    content = open("${path}", encoding="utf-8").read()
    required = ${builtins.toJSON requiredFragments}
    assert all(fragment in content for fragment in required)
    print("${success}")
  '';
in {
  "rpcsvc-proto" = testing.mkQualificationPackageProbe {
    name = "rpcsvc-proto";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "rpcsvc-proto";
      primary = {
        input = "An RPC language definition containing one structure and XDR procedure.";
        operation = "Generate its public C declarations with rpcgen and inspect the emitted interface.";
        expected = "The header declares the answer structure and its XDR function.";
        files = {
          "answer.x" = ''
            struct answer {
                int value;
            };
          '';
          "verify.py" = verificationProgram {
            path = "answer.h";
            requiredFragments = ["struct answer" "xdr_answer"];
            success = "rpcgen output passed";
          };
        };
        steps = [
          {
            argv = ["@out@/bin/rpcgen" "-h" "-o" "answer.h" "answer.x"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "verify.py"];
            exit_code = 0;
            stdout.exact = "rpcgen output passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "An RPC structure whose field declaration lacks a semicolon.";
        operation = "Parse the malformed RPC definition.";
        expected = "rpcgen rejects the syntax error without producing a usable header.";
        files."invalid.x" = "struct answer { int value };\n";
        steps = [
          {
            argv = ["@out@/bin/rpcgen" "-h" "-o" "invalid.h" "invalid.x"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  swig = testing.mkQualificationPackageProbe {
    name = "swig";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "swig";
      primary = {
        input = "A SWIG interface exposing one inline C function to Python.";
        operation = "Generate the Python C wrapper and inspect its registration code.";
        expected = "SWIG emits a wrapper containing the function and module initialization symbols.";
        files = {
          "answer.i" = ''
            %module answer
            %inline %{
            int answer(void) { return 42; }
            %}
          '';
          "verify.py" = verificationProgram {
            path = "answer_wrap.c";
            requiredFragments = ["SWIG_init" "_wrap_answer" "return 42"];
            success = "swig output passed";
          };
        };
        steps = [
          {
            argv = ["@out@/bin/swig" "-python" "-o" "answer_wrap.c" "answer.i"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "verify.py"];
            exit_code = 0;
            stdout.exact = "swig output passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A SWIG inline block with no closing delimiter.";
        operation = "Parse the unterminated interface definition.";
        expected = "SWIG rejects the unterminated block with a syntax failure.";
        files."invalid.i" = "%module invalid\n%inline %{\nint answer(void) { return 42; }\n";
        steps = [
          {
            argv = ["@out@/bin/swig" "-python" "-o" "invalid_wrap.c" "invalid.i"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
