##! tini — Minimal container init process
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "0.19.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "tini";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Tini supervises the child and preserves its output and successful status.";
        "files" = {};
        "input" = "A child shell that prints one fixed line.";
        "operation" = "Run the child under Tini in subreaper mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/tini"
              "-s"
              "--"
              "@bash@"
              "-c"
              "printf 'answer=42\\n'"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Tini reports the spawn failure through status 127.";
        "files" = {};
        "input" = "An absolute child path that does not exist.";
        "operation" = "Ask Tini to spawn the missing child.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/tini"
              "-s"
              "--"
              "/qualification/missing-child"
            ];
            "exit_code" = 127;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://github.com/krallin/tini/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-D9NacDAFKs2fWJSNHZAP4eQy7jcQPFVhVUQIvaxrvw0=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];
    # The upstream project predates CMake 4's minimum policy version.
    cmakeFlags = "-DMINIMAL=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5";

    postInstall = ''
      test -x "$out/bin/tini"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-tini";
        tool = self;
        command = "tini --version";
      };
    };

    meta = {
      description = "Minimal init process for containers";
      homepage = "https://github.com/krallin/tini";
      license = "MIT";
      mainProgram = "tini";
    };
  }
