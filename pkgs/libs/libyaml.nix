##! libyaml — YAML 1.1 parser and emitter library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.2.5";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libyaml";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parser reaches stream end after observing the answer and 42 scalars.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libyaml primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libyaml rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <yaml.h>\nint main(void) {\n    const unsigned char input[] = \"answer: 42\\n\"; int answer = 0, value = 0, done = 0;\n    yaml_parser_t parser; yaml_event_t event;\n    if (!yaml_parser_initialize(&parser)) return 2;\n    yaml_parser_set_input_string(&parser, input, sizeof(input) - 1);\n    while (!done && yaml_parser_parse(&parser, &event)) {\n        if (event.type == YAML_SCALAR_EVENT && strcmp((char *)event.data.scalar.value, \"answer\") == 0) answer = 1;\n        if (event.type == YAML_SCALAR_EVENT && strcmp((char *)event.data.scalar.value, \"42\") == 0) value = 1;\n        done = event.type == YAML_STREAM_END_EVENT; yaml_event_delete(&event);\n    }\n    yaml_parser_delete(&parser);\n    return answer && value && done ? pass() : 3;\n}\n\n";
        };
        "input" = "A YAML mapping whose answer value is 42.";
        "operation" = "Parse the stream and observe its scalar events.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lyaml"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libyaml primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The parser returns failure before stream end.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libyaml primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libyaml rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <yaml.h>\nint main(void) {\n    const unsigned char input[] = \"answer: [1, 2\\n\"; int failed = 0, done = 0;\n    yaml_parser_t parser; yaml_event_t event;\n    if (!yaml_parser_initialize(&parser)) return 2;\n    yaml_parser_set_input_string(&parser, input, sizeof(input) - 1);\n    while (!done) {\n        if (!yaml_parser_parse(&parser, &event)) { failed = 1; break; }\n        done = event.type == YAML_STREAM_END_EVENT; yaml_event_delete(&event);\n    }\n    yaml_parser_delete(&parser);\n    if (!failed) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A YAML flow sequence with no closing bracket.";
        "operation" = "Parse events until libyaml reports a syntax failure.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lyaml"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libyaml rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://pyyaml.org/download/libyaml/yaml-${version}.tar.gz"];
      hash = "sha256-xkKum3X+4SCy2WxxJTi9LPKDIo0jN98s8piOPAJnjvQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd yaml-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "YAML 1.1 parser and emitter library";
      homepage = "https://pyyaml.org/wiki/LibYAML";
      license = "MIT";
    };
  }
