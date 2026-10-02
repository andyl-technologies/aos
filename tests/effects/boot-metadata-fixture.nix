##! Immutable image bundles and an original authorization for the native bridge.
{
  pkgs,
  lib,
  stateDirectory ? "/build/aos-boot-bootstrap-state",
  acquiredStateDirectory ? "/build/aos-boot-acquired-state",
  preparationScript ? builtins.readFile ./boot-metadata-package/handler.sh,
}: let
  provisioningTypes = import ../../pkgs/system/_aos-storage-provisioning-provider/types.nix {inherit lib;};
  provisioningWire = lib.evalModules {
    inherit lib;
    modules = [
      ../../lib/effects/module.nix
      {
        aos.activation.scope = ["fixture" "provisioning-wire"];
        aos.abilities = {
          provisioningMarker.operations.observe = {
            result.options.marker = lib.mkOption {
              type = provisioningTypes.marker;
              description = "Actual durable marker wire contract.";
            };
            handler.program = pkgs.bash;
            effects.single.input = {};
          };
          provisioningEvaluation.operations.evaluate = {
            result.options = {
              provisioning_plan = lib.mkOption {
                type = provisioningTypes.plan;
                description = "Actual canonical provisioning plan wire contract.";
              };
              canonical_plan = lib.mkOption {
                type = lib.types.str;
                description = "Canonical provisioning plan bytes.";
              };
            };
            handler.program = pkgs.bash;
            effects.single.input = {};
          };
        };
      }
    ];
  };
  schema = name: module:
    pkgs.mkDerivation {
      pname = name;
      version = "1";
      inherit module;
      src = null;
      phases = [
        {
          name = "install";
          script = ''mkdir -p "$out"'';
        }
      ];
    };
  factsSchema = schema "bootstrap-facts-schema" ../../pkgs/tools/_aos-metadata-provider/facts;
  proofSchema = schema "bootstrap-proof-schema" ../../pkgs/boot/_aos-boot-preparations/source-authorization;
  payload =
    (pkgs.writeShellScriptBin "handler" ''
      export PATH=${lib.makeBinPath [pkgs.coreutils pkgs.jq]}
      ${preparationScript}
    '').overrideAttrs (_: {
      catalogName = "boot-bootstrap-fixture";
      version = "1";
      module = ./boot-metadata-package;
      moduleDeps = [factsSchema proofSchema];
    });
  packages = [payload];
  acquiredPackage = pkgs.mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "boot-acquired-fixture";
    version = "1.0.0";
    module = ./boot-metadata-acquired;
    meta = {
      mainProgram = "acquired-handler";
      description = "Unbundled native configuration fixture";
      license = "MIT";
      maintainers = ["publisher@example.test"];
    };
    src = null;
    runtimeDeps = [pkgs.bash pkgs.coreutils pkgs.jq];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/acquired-handler" <<'HANDLER'
          #!${pkgs.bash}/bin/bash
          export PATH=${lib.makeBinPath [pkgs.coreutils pkgs.jq]}
          ${builtins.readFile ./boot-metadata-package/handler.sh}
          HANDLER
          chmod +x "$out/bin/acquired-handler"
        '';
      }
    ];
  };
  scope = ["profile" "system"];
  host = lib.evalPackageModules {inherit scope packages;};
  bundle = import ../../pkgs/containers/_aos-oci-backend/deployment-bundle.nix;
  hostBundle = bundle {
    inherit lib pkgs packages scope;
    system = pkgs.stdenv.hostPlatform.system;
    graph = host.deployment.graph;
    withProfileRecords = true;
  };
  hostText = ''
    { config, ... }: {
      aos.apm.desiredPackages = ["boot-bootstrap-fixture"];
      aos.bootstrapFixture.stateDir = ${builtins.toJSON stateDirectory};
      aos.bootstrapFixture.value = "authorized-" + config.host.facts.hostname;
    }
  '';
  receipt =
    pkgs.runCommand "boot-original-authorization.json" {
      buildInputs = [pkgs.python3];
    } ''
      rmdir "$out"
      ${pkgs.python3}/bin/python3 - ${hostBundle}/evaluation.json "$out" <<'PYTHON'
      import hashlib, json, sys
      descriptor = json.load(open(sys.argv[1]))
      host = ${builtins.toJSON hostText}
      facts = dict(hostname="observed-fixture",ssh_authorized_keys=[],instance_id=None,
                   region=None,availability_zone=None,mac_to_iface=[],disk_ids=[],network=None)
      canonical = lambda value: json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
      sha = lambda value: 'sha256:' + hashlib.sha256(value).hexdigest()
      receipt = dict(schema="aos.metadata.authorized-provisioning-input/v1",source="operator",
          host_module=host,host_module_sha256=sha(host.encode()),
          authorization=dict(trust_mode="platform",platform_id="nocloud",signer=None),
          facts=dict(schema="aos.metadata.observed-instance-facts/v1",trust="unauthenticated-observational",
              value=facts,sha256=sha(b'aos.metadata.observed-instance-facts/v1\0'+canonical(facts))),
          base_library=dict(store_path=descriptor['library'].rsplit('/',1)[0],nar_hash=descriptor['libraryNarHash']))
      open(sys.argv[2],'wb').write(canonical(receipt))
      PYTHON
    '';
  plan = pkgs.writeTextFile {
    name = "boot-committed-provisioning-plan.json";
    text = builtins.toJSON {
      schema = "aos.provisioning-plan/v1";
      storage.partitions.var = {
        device = null;
        label = "var";
        type = "linux-generic";
        sizeMin = "4G";
        sizeMax = null;
        weight = 1000;
        format = null;
        uuid = null;
        grow = true;
        growFs = true;
        priority = 9000;
      };
    };
  };
  initrdPolicy = {
    aos.abilities.storageProvisioning.operations.prepare.effects.system.input = {
      stateDir = stateDirectory;
      authorized_input = toString receipt;
      committed_plan = toString plan;
    };
  };
  initrdSource = pkgs.writeTextFile {
    name = "boot-initrd-fixture-policy.nix";
    # Serialize the original authored fixture policy, before module merging.
    # Image evaluation and retained replay consume the same definitions.
    text = "builtins.fromJSON ${builtins.toJSON (builtins.toJSON initrdPolicy)}";
  };
  initrdScope = ["bootstrap-fixture" "initrd"];
  initrd = lib.evalPackageModules {
    inherit packages;
    scope = initrdScope;
    operatorModules = [initrdPolicy];
  };
  initrdBundle = bundle {
    inherit lib pkgs packages;
    scope = initrdScope;
    system = pkgs.stdenv.hostPlatform.system;
    configuration = [initrdSource];
    inputs = [receipt plan hostBundle];
    graph = initrd.deployment.graph;
  };
  binding = pkgs.writeTextFile {
    name = "boot-metadata-binding.json";
    text = builtins.toJSON {
      schema = "aos.boot.metadata-binding";
      version = 1;
      metadataSourceRequired = true;
      scope = initrdScope;
      effect = builtins.hashString "sha256" (builtins.toJSON initrd.config.aos.abilities.storageProvisioning.operations.prepare.effects.system.contract.identity);
    };
  };
in
  (pkgs.writeTextFile {
    name = "boot-bootstrap-fixture";
    destination = "/fixture.json";
    text = builtins.toJSON {
      inherit hostBundle initrdBundle binding;
      inherit stateDirectory acquiredStateDirectory;
      library = lib.packageModuleLibrary;
      # Publication roots are deliberately outside the baseline input closure.
      acquiredRuntimePayloads = map (dependency:
        builtins.unsafeDiscardStringContext (toString dependency))
      acquiredPackage.runtimeDeps;
      acquiredPackage = builtins.unsafeDiscardStringContext (toString acquiredPackage);
      acquiredEnvelope = builtins.unsafeDiscardStringContext (toString acquiredPackage.deploymentArtifact);
    };
  }).overrideAttrs (previous: {
    phases =
      previous.phases
      ++ [
        {
          name = "provisioning-wire";
          script = ''
            cat > "$out/provisioning-wire-graph.json" <<'PROVISIONING_WIRE'
            ${builtins.toJSON provisioningWire.config.aos.activation.graph}
            PROVISIONING_WIRE
          '';
        }
      ];
  })
  // {inherit acquiredPackage receipt plan;}
