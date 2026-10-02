##! Garage — S3-compatible distributed object store
##!
##! Pure-Rust, single-binary, embedded storage (LMDB/sqlite via
##! bundled-libs) — which is what makes it the right S3 fixture for AOS
##! tests: `aos`/`apr`'s s3:// cache backend (crates/aos-net/src/
##! protocol/s3.rs) needs a real SigV4 endpoint to be exercised against,
##! and garage provides one with no external services. See the
##! origin-upload-s3 test in pkgs/tools/aos/_tests.nix.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  service-management,
  aos-filesystem-provider,
}: let
  version = "2.3.0";
  src = fetchurl {
    urls = [
      "https://git.deuxfleurs.fr/Deuxfleurs/garage/archive/v${version}.tar.gz"
    ];
    hash = "sha256-uDqYFndnazVAC7uvIJdMOW8y2jHHx2MM5V/D5iwOLgE=";
  };
in
  mkCargoPackage {
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
    pname = "garage";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Garage returns success and reports its version.";
        "files" = {};
        "input" = "The packaged Garage server's release identity.";
        "operation" = "Request its version without opening storage or network listeners.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/garage\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"garage\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"garage operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "garage operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Garage rejects the unsupported command.";
        "files" = {};
        "input" = "A Garage invocation naming an unknown command.";
        "operation" = "Parse the unsupported command without opening storage.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/garage\", \"aos-invalid-command\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"garage rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "garage rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-EzUMASYQl7/W3cnfYTbwEazNnhZUtdIALfztWk3Qvb8=";
    };

    # Build only the garage binary from the workspace. The default
    # features bundle the sqlite and LMDB C sources, so no system
    # libraries are needed beyond the stdenv C compiler.
    cargoFlags = "-p garage";
    doCheck = false;
    runtimeDeps = [];

    module = ./_garage-config;
    moduleDeps = [service-management aos-filesystem-provider];

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: let
      secret = name: name;
      evaluate = settings:
        lib.evalPackageModules {
          scope = ["package-check" "garage"];
          packages = [self];
          operatorModules = [{aos.garage = settings;}];
        };
      evaluated = evaluate {
        enable = true;
        dbEngine = "sqlite";
        replicationFactor = 1;
        rpc = {
          bindAddress = "127.0.0.1:43901";
          publicAddress = "127.0.0.1:43901";
          bootstrapPeers = ["0000000000000000000000000000000000000000000000000000000000000000@127.0.0.1:43909"];
          secret.name = secret "rpc-secret";
        };
        s3 = {
          bindAddress = "127.0.0.1:43900";
          region = "aos-test";
          rootDomain = ".s3.test";
        };
        web = {
          enable = true;
          bindAddress = "127.0.0.1:43902";
          rootDomain = ".web.test";
        };
      };
      disabled = evaluate {};
      evaluatedAdmin = evaluate {
        enable = true;
        rpc.secret.name = secret "rpc-secret";
        admin = {
          enable = true;
          token.name = secret "admin-token";
          metrics.token.name = secret "metrics-token";
        };
      };
      evaluatedAdminWithoutMetricsToken = evaluate {
        enable = true;
        rpc.secret.name = secret "rpc-secret";
        admin = {
          enable = true;
          token.name = secret "admin-token";
          metrics.requireToken = false;
        };
      };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      invalidRpc = evaluate {enable = true;};
      invalidAdmin = evaluate {
        enable = true;
        rpc.secret.name = secret "rpc-secret";
        admin.enable = true;
      };
      invalidPeers = evaluate {
        rpc = {
          secret.name = secret "rpc-secret";
          bootstrapPeers = ["same@host:3901" "same@host:3901"];
        };
      };
      renderedConfig = builtins.toFile "garage-runtime-check.toml" ''
        metadata_dir = "/var/lib/aos-pkg-garage/meta"
        data_dir = "/var/lib/aos-pkg-garage/data"
        db_engine = "sqlite"
        replication_factor = 1
        rpc_bind_addr = "127.0.0.1:43901"

        [s3_api]
        api_bind_addr = "127.0.0.1:43900"
        s3_region = "aos-test"
      '';
      nativeTests = import ./_garage-config/native-tests.nix {inherit lib evaluated disabled evaluatedAdmin evaluatedAdminWithoutMetricsToken invalidRpc invalidAdmin invalidPeers;};
      contractHolds = builtins.all (value: value) (builtins.attrValues nativeTests);
    in {
      version = testing.mkToolCheck {
        pname = "storage-garage";
        tool = self;
        command = "garage --version";
      };

      native-module-contract =
        if contractHolds
        then
          pkgs.runCommand "storage-garage-native-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the Garage native module contract checks failed";

      lifecycle = import ./_garage-tests/lifecycle.nix {
        inherit testing self renderedConfig;
        coreutils = pkgs.coreutils;
        grep = pkgs.grep;
        iproute2 = pkgs.iproute2;
      };
    };

    meta = {
      description = "Garage — S3-compatible distributed object storage service";
      homepage = "https://garagehq.deuxfleurs.fr";
      license = "AGPL-3.0";
    };
  }
