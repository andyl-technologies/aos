# Private original operator; ordinary packages and flight profiles stay separate.
{
  pkgs,
  lib,
  ownedRootfs,
  kernel,
  initrd,
  externalSource,
  dependencyRoots,
  operatorPolicy,
  actorInventory,
  sourceManifest,
  workflow,
}: let
  source = import ./_source.nix {inherit lib;};
  qemu = pkgs.qemu-crucible;
  correspondingSource = pkgs.qemu-crucible-source;
  qemuExecutable = "${qemu}/bin/qemu-system-x86_64";
  sourceFields = ["residentBytes" "backingBytes" "tasks" "descriptors" "totalMetadataBytes"];
  validSource = builtins.all (name:
    externalSource ? ${name}
    && builtins.isInt externalSource.${name}
    && externalSource.${name} > 0)
  sourceFields;
  inventory = pkgs.mkDerivation {
    pname = "crucible-private-parent-qemu-inventory";
    version = "0";
    src = null;
    buildDeps = [pkgs.python3];
    runtimeDeps = [pkgs.crucible correspondingSource] ++ dependencyRoots;
    phases = [
      {
        name = "describe-installed-qemu";
        script = ''
          mkdir -p "$out/share/crucible"
          ${pkgs.python3}/bin/python3 ${../../../tests/crucible/measurement-image-inventory.py} \
            --image ${qemuExecutable} \
            ${builtins.concatStringsSep " " (map (root: "--dependency-root ${root}") dependencyRoots)} \
            --output "$out/share/crucible/parent-images.json"
          ln -s ${source} "$out/source"
          ln -s ${pkgs.crucible} "$out/suite"
          ln -s ${correspondingSource} "$out/corresponding-source"
        '';
      }
    ];
  };
  parent = pkgs.mkCargoPackage {
    pname = "crucible-private-original-parent";
    version = "0";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoEnv = {
      OPENSSL_DIR = "${pkgs.openssl}";
      OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
      OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
      OPENSSL_NO_VENDOR = "1";
      OPENSSL_STATIC = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      PROTOC = "${pkgs.protobuf}/bin/protoc";
      CRUCIBLE_PARENT_SOURCE_RESIDENT = toString externalSource.residentBytes;
      CRUCIBLE_PARENT_SOURCE_BACKING = toString externalSource.backingBytes;
      CRUCIBLE_PARENT_SOURCE_TASKS = toString externalSource.tasks;
      CRUCIBLE_PARENT_SOURCE_FDS = toString externalSource.descriptors;
      CRUCIBLE_PARENT_OPERATOR = "${operatorPolicy}";
      CRUCIBLE_PARENT_ACTOR_INVENTORY = "${actorInventory}";
      CRUCIBLE_PARENT_SOURCE_MANIFEST = "${sourceManifest}";
      CRUCIBLE_PARENT_TOTAL_METADATA = toString externalSource.totalMetadataBytes;
      CRUCIBLE_PARENT_CGROUP = "/sys/fs/cgroup/system.slice/crucible-campaign.service/workload";
      CRUCIBLE_PARENT_WORKFLOW = "${workflow}/share/crucible/resident-workflow/workflow.json";
      CRUCIBLE_PARENT_INVENTORY = "${inventory}/share/crucible/parent-images.json";
      CRUCIBLE_PARENT_QEMU = qemuExecutable;
      CRUCIBLE_PARENT_ROOTFS = "${ownedRootfs}";
      CRUCIBLE_PARENT_KERNEL = "${kernel}";
      CRUCIBLE_PARENT_INITRD = "${initrd}";
    };
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-cli --bin crucible --features private-parent-fixture"
    ];
    doCheck = false;
    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.protobuf];
    runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.crucible correspondingSource inventory ownedRootfs kernel initrd operatorPolicy actorInventory sourceManifest workflow];
    nukeRefsKeep = [qemu correspondingSource inventory ownedRootfs kernel initrd operatorPolicy actorInventory sourceManifest workflow];
    passthru = {
      privateFixture = true;
      runtimeAdmission = false;
      sourceCohort = source;
    };
  };
in
  assert validSource;
  assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";
  assert qemu.passthru.qemuBuildIdentity == correspondingSource.passthru.qemuBuildIdentity;
  assert dependencyRoots != [];
  assert ownedRootfs.passthru.installedImages.passthru.sourceCohort == source;
  assert ownedRootfs.passthru.operatorPolicy == operatorPolicy;
  assert ownedRootfs.passthru.imageInventory == actorInventory;
  assert ownedRootfs.passthru.sourceManifest == sourceManifest;
  assert ownedRootfs.passthru.workflow == workflow;
    pkgs.mkDerivation {
      pname = "crucible-private-parent-fixture";
      version = "0";
      src = null;
      buildDeps = [pkgs.bash];
      runtimeDeps = [parent pkgs.crucible correspondingSource inventory];
      phases = [
        {
          name = "assemble-owned-operator";
          script = ''
            mkdir -p "$out/bin" "$out/nix-support"
            cat > "$out/bin/crucible-private-parent" <<'ENTRY'
            #!${pkgs.bash}/bin/bash
            exec ${parent}/bin/crucible serve --production-qemu --listen 127.0.0.1:0 --trusted-unauthenticated-bind
            ENTRY
            chmod +x "$out/bin/crucible-private-parent"
            ln -s ${source} "$out/source"
            ln -s ${inventory} "$out/installed-inventory"
            ln -s ${pkgs.crucible} "$out/suite"
            ln -s ${correspondingSource} "$out/corresponding-source"
            cat > "$out/nix-support/aos-release-policy" <<'POLICY'
            policy_version=1
            artifact_role=private-test-fixture
            standalone_release=false
            POLICY
          '';
        }
      ];
      passthru = {
        inherit parent inventory externalSource;
        controller = parent;
        privateFixture = true;
        runtimeAdmission = false;
      };
    }
