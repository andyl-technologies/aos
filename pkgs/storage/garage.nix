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
    pname = "garage";
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

    abilities = ./_garage-config/module.nix;

    checks = {
      testing,
      self,
      pkgs,
    }: let
      serviceManagement = lib.abilities.interfaces.serviceManagement;
      environmentId = lib.abilities.environmentId {
        authority = "deployment";
        key = "garage-test";
        stage = "host";
      };
      environment = builtins.removeAttrs environmentId ["_type"];
      credentialProvider = lib.abilities.instanceId {
        environment = environmentId;
        key = "credential-provider";
      };
      qualifiedResultOf = request: output: {
        _type = "aos-request-output-reference";
        inherit request output;
      };
      secret = name:
        lib.abilities.resourceReference {
          interface = serviceManagement.interfaces.credentialDelivery.identity;
          resource = {
            provider = credentialProvider;
            key = name;
          };
          operations = ["observe"];
          lifetime = "persistent";
        };
      evaluate = garageConfig:
        lib.evalModules {
          modules = [
            ../../modules/abilities/default.nix
            {
              options.assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
                contributable = true;
              };
              aos.abilities.environment = environment;
              garage = garageConfig;
            }
          ];
          packageModules = [
            {
              name = "garage";
              module.imports = [./_garage-config/module.nix];
            }
          ];
          inherit lib;
        };
      evaluated = evaluate {
        enable = true;
        dbEngine = "sqlite";
        replicationFactor = 1;
        rpc = {
          bindAddress = "127.0.0.1:43901";
          publicAddress = "127.0.0.1:43901";
          bootstrapPeers = ["0000000000000000000000000000000000000000000000000000000000000000@127.0.0.1:43909"];
          secret.resource = secret "rpc-secret";
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
        rpc.secret.resource = secret "rpc-secret";
        admin = {
          enable = true;
          token.resource = secret "admin-token";
          metrics.token.resource = secret "metrics-token";
        };
      };
      evaluatedAdminWithoutMetricsToken = evaluate {
        enable = true;
        rpc.secret.resource = secret "rpc-secret";
        admin = {
          enable = true;
          token.resource = secret "admin-token";
          metrics.requireToken = false;
        };
      };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      invalidRpc = evaluate {enable = true;};
      invalidAdmin = evaluate {
        enable = true;
        rpc.secret.resource = secret "rpc-secret";
        admin.enable = true;
      };
      invalidPeers = evaluate {
        rpc = {
          secret.resource = secret "rpc-secret";
          bootstrapPeers = ["same@host:3901" "same@host:3901"];
        };
      };
      abilities = evaluated.config.aos.abilities;
      disabledAbilities = disabled.config.aos.abilities;
      adminAbilities = evaluatedAdmin.config.aos.abilities;
      adminWithoutMetricsTokenAbilities = evaluatedAdminWithoutMetricsToken.config.aos.abilities;
      requests = builtins.attrNames abilities.requests;
      disabledRequirements = builtins.attrNames disabledAbilities.requirementTemplates;
      adminRequests = builtins.attrNames adminAbilities.requests;
      adminWithoutMetricsTokenRequests = builtins.attrNames adminWithoutMetricsTokenAbilities.requests;
      configurationSource = abilities.requests."garage:server-configuration".parameters.source;
      servicePrincipal = abilities.requests."garage:service-principal".parameters;
      mainStorageMounts = abilities.requests."garage:main-storage".parameters.mounts;
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
      contractHolds =
        assertionsHold evaluated
        && !assertionsHold invalidRpc
        && !assertionsHold invalidAdmin
        && !assertionsHold invalidPeers
        && disabledAbilities.instances == {}
        && disabledAbilities.requests == {}
        && builtins.elem "garage:credential-delivery" disabledRequirements
        && builtins.elem "garage:service-lifecycle" disabledRequirements
        && builtins.elem "garage:main-lifecycle" requests
        && builtins.elem "garage:main-storage" requests
        && builtins.elem "garage:service-principal" requests
        && builtins.elem "garage:credential-rpc-secret" requests
        && !(builtins.elem "garage:credential-admin-token" requests)
        && builtins.elem "garage:credential-admin-token" adminRequests
        && builtins.elem "garage:credential-metrics-token" adminRequests
        && builtins.elem "garage:credential-admin-token" adminWithoutMetricsTokenRequests
        && !(builtins.elem "garage:credential-metrics-token" adminWithoutMetricsTokenRequests)
        && servicePrincipal.home_directory
        == qualifiedResultOf "garage:home-storage" "planned-path"
        && builtins.map (mount: mount.source) mainStorageMounts
        == [
          (qualifiedResultOf "garage:metadata-storage" "planned-path")
          (qualifiedResultOf "garage:data-storage" "planned-path")
          (qualifiedResultOf "garage:runtime-storage" "planned-path")
        ]
        && configurationSource.kind == "structured-value"
        && configurationSource.format == "toml"
        && !(lib.hasInfix "/var/lib/aos-pkg-garage" (builtins.toJSON configurationSource))
        && !(lib.hasInfix "rpc-secret" (builtins.toJSON configurationSource));
    in {
      version = testing.mkToolCheck {
        pname = "storage-garage";
        tool = self;
        command = "garage --version";
      };

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "storage-garage-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the Garage ability module contract checks failed";

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
