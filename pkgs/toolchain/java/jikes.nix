##! jikes — Jikes Java compiler (C++ implementation, outputs Java 1.4 bytecode)
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
}: let
  version = "1.22";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "jikes";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Jikes emits a classfile containing the declared answer constant.";
        "files" = {
          "Answer.java" = "public class Answer { public static final int VALUE = 42; }\n";
          "java/io/Serializable.java" = "package java.io; public interface Serializable {}\n";
          "java/lang/Object.java" = "package java.lang; public class Object {}\n";
          "java/lang/String.java" = "package java.lang; public final class String {}\n";
        };
        "input" = "A Java class with a constant answer and the compiler's minimal bootstrap types.";
        "operation" = "Compile the sources to Java 1.4 classfiles with Jikes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/jikes\", \"-bootclasspath\", \".\", \"java/lang/Object.java\", \"java/lang/String.java\", \"java/io/Serializable.java\", \"Answer.java\"], capture_output=True, text=True)\nassert result.returncode == 0, (result.stdout, result.stderr)\nclassfile = pathlib.Path(\"Answer.class\").read_bytes()\nassert classfile[:8] == bytes.fromhex(\"cafebabe00000030\")\nassert b\"VALUE\" in classfile and bytes.fromhex(\"0000002a\") in classfile\nprint(\"jikes operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "jikes operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Jikes reports a syntax error and does not emit the requested classfile.";
        "files" = {
          "Broken.java" = "public class Broken {\n";
          "java/io/Serializable.java" = "package java.io; public interface Serializable {}\n";
          "java/lang/Object.java" = "package java.lang; public class Object {}\n";
          "java/lang/String.java" = "package java.lang; public final class String {}\n";
        };
        "input" = "A Java class whose body is missing its closing brace.";
        "operation" = "Compile the malformed source with the same minimal bootstrap types.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport pathlib, subprocess\nresult = subprocess.run([\"@out@/bin/jikes\", \"-bootclasspath\", \".\", \"java/lang/Object.java\", \"java/lang/String.java\", \"java/io/Serializable.java\", \"Broken.java\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"Syntax Error\" in (result.stdout + result.stderr)\nassert not pathlib.Path(\"Broken.class\").exists()\n\nsys.stderr.write(\"jikes rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "jikes rejected invalid input\n";
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
      urls = [
        "https://downloads.sourceforge.net/project/jikes/Jikes/${version}/jikes-${version}.tar.bz2"
      ];
      hash = "sha256-DLAsdjvEQTSfbTjKzVKt92IwLM46COJp8fdfcm5uFOM=";
    };

    buildDeps =
      [gnumake]
      ++ (
        if isDarwinCross
        then [buildPackages.automake]
        else []
      );
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jikes-${version}
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
              # Jikes predates AArch64 and otherwise treats a target C++
              # executable as a runnable configure probe. Refresh only the
              # canonical triplet table and use the stdenv cross tuple.
              cp ${buildPackages.automake}/share/automake-*/config.sub config.sub

            # Jikes targets the pre-C++17 language where `register` remains
            # accepted; modern Clang otherwise rejects its bundled inflater.
            CXXFLAGS="-fpermissive -std=gnu++14" \
              ./configure $configureFlags --prefix=$out
          ''
          else ''
            CXXFLAGS="-fpermissive" ./configure --prefix=$out
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
      description = "Jikes — fast Java compiler written in C++";
      homepage = "https://jikes.sourceforge.net/";
      license = "IPL-1.0";
    };
  }
