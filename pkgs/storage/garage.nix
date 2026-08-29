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
  bash,
  coreutils,
  writeShellScriptBin,
}: let
  version = "2.3.0";
  src = fetchurl {
    urls = [
      "https://git.deuxfleurs.fr/Deuxfleurs/garage/archive/v${version}.tar.gz"
    ];
    hash = "sha256-uDqYFndnazVAC7uvIJdMOW8y2jHHx2MM5V/D5iwOLgE=";
  };
  control = writeShellScriptBin "garage-control" ''
    set -euo pipefail

    runtime=/etc/aos/packages/garage/runtime.env
    config=/etc/aos/packages/garage/garage.toml

    enabled() {
      set -a
      source "$runtime"
      set +a
      [[ "''${GARAGE_ENABLED:-0}" == 1 ]]
    }

    use_credential() {
      local variable="$1"
      local name="$2"
      local source="''${CREDENTIALS_DIRECTORY:-}/$name"
      if [[ -n "''${CREDENTIALS_DIRECTORY:-}" && -r "$source" ]]; then
        export "$variable=$source"
      fi
    }

    case "''${1:-}" in
      enabled)
        enabled
        ;;
      prepare)
        ${coreutils}/bin/install -d -m 0750 \
          /var/lib/aos-pkg-garage/meta \
          /var/lib/aos-pkg-garage/data
        ;;
      run)
        use_credential GARAGE_RPC_SECRET_FILE rpc-secret
        use_credential GARAGE_ADMIN_TOKEN_FILE admin-token
        use_credential GARAGE_METRICS_TOKEN_FILE metrics-token
        exec /bin/garage -c "$config" server
        ;;
      *)
        echo "usage: garage-control {enabled|prepare|run}" >&2
        exit 64
        ;;
    esac
  '';
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
    runtimeDeps = [bash coreutils control];

    postInstall = ''
      ln -s ${control}/bin/garage-control "$out/bin/garage-control"
      test -x "$out/bin/garage-control"
    '';

    expose = {
      units = {
        "garage-prepare.service" = {
          description = "Prepare Garage state";
          before = ["garage.service"];
          serviceConfig = {
            Type = "oneshot";
            User = "garage";
            Group = "garage";
            EnvironmentFile = "/etc/aos/packages/garage/runtime.env";
            ExecCondition = "/bin/garage-control enabled";
            ExecStart = "/bin/garage-control prepare";
            StateDirectory = "aos-pkg-garage";
            StateDirectoryMode = "0750";
            RuntimeDirectory = "garage";
            RuntimeDirectoryMode = "0750";
            RemainAfterExit = true;
            UMask = "0027";
          };
        };

        "garage.service" = {
          description = "Garage object-storage server";
          after = ["network.target" "garage-prepare.service"];
          requires = ["garage-prepare.service"];
          restartIfChanged = true;
          stopOnRemoval = true;
          serviceConfig = {
            Type = "simple";
            User = "garage";
            Group = "garage";
            EnvironmentFile = "/etc/aos/packages/garage/runtime.env";
            ExecCondition = "/bin/garage-control enabled";
            ExecStart = "/bin/garage-control run";
            Restart = "on-failure";
            RestartSec = "5s";
            TimeoutStopSec = "60s";
            StateDirectory = "aos-pkg-garage";
            StateDirectoryMode = "0750";
            RuntimeDirectory = "garage";
            RuntimeDirectoryMode = "0750";
            LogsDirectory = "garage";
            LogsDirectoryMode = "0750";
            UMask = "0027";
            LimitNOFILE = "65536";
          };
        };
      };

      config = {
        artifacts = [
          {
            name = "runtime";
            path = "/etc/aos/packages/garage/runtime.env";
            format = "env";
            required = ["GARAGE_CONFIG_GENERATION" "GARAGE_ENABLED"];
            units = ["garage-prepare.service" "garage.service"];
            reload = "restart";
          }
        ];
        credentials =
          builtins.map (name: {
            inherit name;
            source = "/run/credstore/garage/${name}";
            units = ["garage.service"];
            encrypted = false;
            optional = true;
          }) [
            "rpc-secret"
            "admin-token"
            "metrics-token"
          ];
      };

      permissions = {
        network = "host";
        capabilities = [];
        devices = [];
        host-paths = [
          {
            path = "/etc/aos/packages/garage/garage.toml";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
        security-label = "aos-pkg-garage";
      };
    };

    configModule = {
      src = ./_garage-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "garage.admin.bindAddress"
        "garage.admin.enable"
        "garage.admin.metrics.requireToken"
        "garage.admin.metrics.token"
        "garage.admin.token"
        "garage.dbEngine"
        "garage.enable"
        "garage.replicationFactor"
        "garage.rpc.bindAddress"
        "garage.rpc.bootstrapPeers"
        "garage.rpc.publicAddress"
        "garage.rpc.secret"
        "garage.s3.bindAddress"
        "garage.s3.region"
        "garage.s3.rootDomain"
        "garage.web.bindAddress"
        "garage.web.enable"
        "garage.web.rootDomain"
      ];
      ownsRoots = [
        {
          root = "garage";
          interfaceAbi = 1;
        }
      ];
      artifacts = {
        etc = ["aos/packages/garage/garage.toml"];
        units = [];
        users = ["garage"];
        groups = ["garage"];
      };
      documentation = {
        summary = "Typed Garage S3, RPC, Web, administration, credential, and persistence configuration.";
        sections = {
          lifecycle = lib.aosDoc.section "State and lifecycle" [
            (lib.aosDoc.paragraph "Garage retains metadata and object data in package state and performs compatible migrations during startup. Configuration changes restart the daemon rather than pretending TOML is reloadable.")
          ];
          cluster = lib.aosDoc.section "Cluster identity" [
            (lib.aosDoc.paragraph "The RPC secret is a 32-byte cluster key encoded as 64 hexadecimal characters. Bootstrap peers and public addresses must remain stable across members.")
          ];
          credentials = lib.aosDoc.section "Administration credentials" [
            (lib.aosDoc.paragraph "RPC, administrator, and metrics tokens are opaque references projected through service credentials and *_FILE interfaces, never TOML or process arguments.")
          ];
        };
      };
    };

    checks = {
      testing,
      self,
      pkgs,
    }: let
      moduleStub = {
        options = {
          assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
          garage.config = lib.mkOption {
            type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
            default = {};
          };
          garage.credentials = lib.mkOption {
            type = lib.types.attrsOf lib.types.attrs;
            default = {};
          };
          environment.etc = lib.mkOption {
            type = lib.types.attrsOf lib.types.attrs;
            default = {};
          };
          aos.users.users = lib.mkOption {
            type = lib.types.attrsOf lib.types.attrs;
            default = {};
          };
          aos.users.groups = lib.mkOption {
            type = lib.types.attrsOf lib.types.attrs;
            default = {};
          };
        };
      };
      evaluate = value:
        lib.evalModules {
          modules = [moduleStub ./_garage-config/module.nix {garage = value;}];
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
          secret.ref = "system-credential:garage-rpc";
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
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      invalidRpc = evaluate {enable = true;};
      invalidAdmin = evaluate {
        rpc.secret.ref = "system-credential:garage-rpc";
        admin.enable = true;
      };
      invalidPeers = evaluate {
        rpc = {
          secret.ref = "system-credential:garage-rpc";
          bootstrapPeers = ["same@host:3901" "same@host:3901"];
        };
      };
      rendered = evaluated.config.environment.etc."aos/packages/garage/garage.toml".text;
      renderedConfig = builtins.toFile "garage-config-module-check.toml" rendered;
      signedExpose = builtins.fromJSON self.expose.manifest;
      signedCredentials = signedExpose.expose.config.credentials;
      credentialNames = ["rpc-secret" "admin-token" "metrics-token"];
      credentialContract =
        builtins.length signedCredentials
        == builtins.length credentialNames
        && builtins.all (credential:
          builtins.elem credential.name credentialNames
          && credential.source == "/run/credstore/garage/${credential.name}"
          && !credential.encrypted
          && credential.optional
          && credential.units == ["garage.service"])
        signedCredentials;
      contractHolds =
        assertionsHold evaluated
        && !assertionsHold invalidRpc
        && !assertionsHold invalidAdmin
        && !assertionsHold invalidPeers
        && credentialContract;
    in {
      version = testing.mkToolCheck {
        pname = "storage-garage";
        tool = self;
        command = "garage --version";
      };

      config-module-contract =
        if contractHolds
        then
          pkgs.runCommand "storage-garage-config-module-contract" {} ''
            test -f ${self.config}/module.nix
            grep -q '"root":"garage"' ${self.config}/config-meta.json
            grep -Fq 'metadata_dir = "/var/lib/aos-pkg-garage/meta"' ${renderedConfig}
            grep -Fq 'db_engine = "sqlite"' ${renderedConfig}
            grep -Fq 'replication_factor = 1' ${renderedConfig}
            grep -Fq 'bootstrap_peers = ["0000000000000000000000000000000000000000000000000000000000000000@127.0.0.1:43909"]' ${renderedConfig}
            grep -Fq '[s3_web]' ${renderedConfig}
            if grep -Eq '(rpc_secret|admin_token|metrics_token)[[:space:]]*=' ${renderedConfig}; then
              echo "Garage rendered secret material or secret paths into TOML" >&2
              exit 1
            fi
            grep -qx 'User=garage' ${self.expose}/units/garage.service
            grep -qx 'StateDirectory=aos-pkg-garage' ${self.expose}/units/garage.service
            grep -qx 'BindReadOnlyPaths=/etc/aos/packages/garage/garage.toml' ${self.expose}/units/garage.service
            grep -Eq '^Requires=.*garage-prepare\.service( |$)' ${self.expose}/units/garage.service
            if grep -Eq 'LoadCredential(Encrypted)?=.*(rpc-secret|admin-token|metrics-token)' ${self.expose}/units/garage.service; then
              echo "optional Garage credentials became unconditional unit bindings" >&2
              exit 1
            fi
            mkdir -p "$out"
            printf '%s\n' PASS >"$out/result"
          ''
        else throw "the Garage config-module contract checks failed";

      config-module-lifecycle = import ./_garage-tests/lifecycle.nix {
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
