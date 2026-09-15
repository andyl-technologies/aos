##! sccache — Shared compilation cache
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  openssl,
}: let
  version = "0.17.0";
  src = fetchurl {
    urls = ["https://github.com/mozilla/sccache/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-SZSa0c8XXEnaEm27DC5qVr2dH2JujMC+F7lmi5FBRcY=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    # sccache 0.17 predates rust-openssl's OpenSSL 4 support.
    cargoPatches = [./sccache-openssl-4.patch];
    hash = "sha256-lnfGDjnTLI4YU2qm5a26ardulbGTIlcfWzk2R9ajg5w=";
  };
in
  mkCargoPackage {
    pname = "sccache";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The cached compiler frontend produces a valid object and the linked program prints 42.";
        "files" = {
          "answer.c" = "#include <stdio.h>\n\nint main(void) {\n    return printf(\"42\\n\") < 0;\n}\n";
        };
        "input" = "A C translation unit that prints a fixed answer.";
        "operation" = "Compile the translation unit through sccache, link it, and execute the result.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/sccache"
              "@cc@"
              "-c"
              "answer.c"
              "-o"
              "answer.o"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@cc@"
              "answer.o"
              "-o"
              "answer"
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
              "@work@/primary/answer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Sccache propagates the compiler's syntax-error status.";
        "files" = {
          "invalid.c" = "int main(void) { int answer = ; return answer; }\n";
        };
        "input" = "A C translation unit with an incomplete initializer.";
        "operation" = "Compile the malformed source through sccache.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/sccache"
              "@cc@"
              "-c"
              "invalid.c"
              "-o"
              "invalid.o"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version src cargoDeps;
    # Keep the build lockfile aligned with the vendored dependency set.
    patches = [./sccache-openssl-4.patch];

    buildDeps = [pkg-config];
    runtimeDeps = [openssl];
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-sccache";
        tool = self;
        command = "sccache --version";
      };
    };
    meta = {
      description = "Compiler cache with local and remote storage support";
      homepage = "https://github.com/mozilla/sccache";
      license = "Apache-2.0";
      mainProgram = "sccache";
    };
  }
