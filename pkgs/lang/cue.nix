##! cue — Data validation, configuration, and schema language tool
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "0.17.1";
  src = fetchurl {
    name = "cue-${version}.tar.gz";
    urls = ["https://github.com/cue-lang/cue/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-MieaUP3TciPOZqGGTTiRTHk45jeOJW/x7Iu3p74LsPw=";
  };
in
  mkGoPackage {
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
      target = [
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
      role = "public-package";
    };

    pname = "cue";
    # CUE is pre-1.0: minor releases can change language semantics.
    # https://cuelang.org/docs/introduction/installation/
    version = "~${version}";
    inherit src;

    goModules = fetchGoModules {
      inherit src;
      hash = "sha256-gOiwTo1GPRQ4cugQNhWERJDdg7IrtPyCt1xaK45g4vE=";
    };
    goPackage = "./cmd/cue";
    # The source root already has a `cue` package directory, so the binary is
    # written to a separate build directory before installation.
    goOutput = ".aos-build/cue";
    preBuild = ''
      mkdir -p .aos-build
    '';

    # Upstream release builds read the module version from Go build info,
    # which a source archive cannot provide; Go records "(devel)" instead.
    # Report the packaged release so `cue version` and the registry client's
    # User-Agent identify the real version.
    postPatch = ''
      sed -i 's|^\treturn cueMod.Version$|\tif cueMod.Version == "(devel)" {\n\t\treturn "v${version}"\n\t}\n\treturn cueMod.Version|' \
        internal/cueversion/version.go
      grep -q 'return "v${version}"' internal/cueversion/version.go
    '';

    # The full suite reruns many thousands of txtar evaluation cases. The
    # command, encoders, module client, and evaluator packages cover the
    # shipped binary; the remaining packages exercise generators and CI tools.
    goTestFlags = "./cmd/... ./cue/... ./encoding/... ./mod/... ./pkg/...";

    postInstall = ''
      mkdir -p "$out/share/licenses/cue"
      cp LICENSE "$out/share/licenses/cue/"
    '';

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A CUE schema unified with concrete data.";
        operation = "Export the unified value as JSON.";
        expected = "CUE emits the concrete, validated document.";
        files = {
          "config.cue" = ''
            #Service: {
            	name: string
            	port: int & >0 & <65536
            }
            service: #Service & {
            	name: "web"
            	port: 8080
            }
          '';
        };
        steps = [
          {
            argv = ["@out@/bin/cue" "export" "--out" "json" "config.cue"];
            exit_code = 0;
            stdout.exact = "{\n    \"service\": {\n        \"name\": \"web\",\n        \"port\": 8080\n    }\n}\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "Concrete data that violates the schema's port bound.";
        operation = "Validate the conflicting value with cue vet.";
        expected = "CUE reports the constraint violation and fails.";
        files = {
          "config.cue" = ''
            #Service: port: int & <65536
            service: #Service & {port: 70000}
          '';
          "probe.py" = ''
            import subprocess, sys

            result = subprocess.run(
                ["@out@/bin/cue", "vet", "config.cue"], capture_output=True, text=True
            )
            assert result.returncode != 0
            assert "invalid value 70000" in result.stderr, result.stderr
            sys.stderr.write("cue rejected invalid input\n")
            raise SystemExit(7)
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "cue rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };

    checks = {
      testing,
      self,
      ...
    }: {
      export = testing.mkToolCheck {
        pname = "tool-cue";
        tool = self;
        command = ''
          cue version | grep -qx 'cue version v${version}'
          printf 'a: int & >1\na: 2\n' > /tmp/config.cue
          cue vet -c /tmp/config.cue
          test "$(cue export -e a /tmp/config.cue)" = 2
          printf 'a: int & >1\na: 0\n' > /tmp/invalid.cue
          ! cue vet -c /tmp/invalid.cue
          echo "cue export passed"
        '';
      };
    };

    meta = {
      description = "Validate, define, and use dynamic and text-based data";
      homepage = "https://cuelang.org/";
      license = "Apache-2.0";
      mainProgram = "cue";
    };
  }
