##! Checks baked disk provenance and the fleet metadata-to-disk dataflow.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = toString (import ./_fixture-payload.nix "test-disk-tools");
  nativePayload = toString (import ./_fixture-payload.nix "test-disk-native-tools");
  captureDerivation = arguments: arguments // {outPath = payload;};
  buildPackages = {
    mkDerivation = captureDerivation;
    writeTextFile = captureDerivation;
    coreutils = nativePayload;
    e2fsprogs = nativePayload;
    fakeroot = nativePayload;
    jq = nativePayload;
    openssh = nativePayload;
    swtpm = nativePayload;
    util-linux = nativePayload;
    runCommand = name: arguments: script: {outPath = nativePayload;};
  };
  packages = {
    inherit buildPackages;
    stdenv.hostPlatform.constraints.cpu = "x86_64";
    mkDerivation = captureDerivation;
    openssh = payload;
    swtpm = payload;
    writeTextFile = captureDerivation;
    runCommand = name: arguments: script: {outPath = payload;};
  };
  buildDisk = import ../../pkgs/system/_systemd-abilities/testing/disk.nix {
    inherit buildPackages lib packages;
    closureInfoFor = _: {outPath = payload;};
  };
  disk = arguments:
    buildDisk ({
        guestArchitecture = "x86_64";
        system.config.aos.security.selinux.protectedSandboxNetworkRoots = {
          enable = false;
          _varRootContext = "system_u:object_r:var_t:s0";
        };
      }
      // arguments);
  assembly = arguments: (builtins.head (disk arguments).phases).script;
  contains = text: needle: builtins.length (lib.splitString needle text) > 1;
  operator = assembly {provisioningSource = "operator";};
  fallback = assembly {};
  uninitialized = assembly {
    varProvisioning = "repart";
    provisioningSource = "operator";
  };
  protected = assembly {
    system.config.aos.security.selinux.protectedSandboxNetworkRoots = {
      enable = true;
      _varRootContext = "system_u:object_r:aos_var_t:s0";
    };
  };
  partitionType = script: name: let
    matches =
      builtins.filter (match: match != null)
      (map (line: builtins.match ".*type=([^,]+), name=${name}.*" line) (lib.splitString "\n" script));
  in
    assert builtins.length matches == 1;
      builtins.head (builtins.head matches);
  fleet = import ../../lib/testing/fleet.nix {
    pkgs = packages;
    inherit lib;
  };
  system = {
    extendModules = _: system;
    config = {
      aos.packages.aos-test-agent.bundle = true;
      aos.image.platform = {
        testKernelParams = [];
        # Capture the actual harness call without constructing a disk image.
        buildTestDisk = {inputs, ...}: {
          outPath = "${payload}/${inputs.provisioningSource}-${inputs.varProvisioning}";
        };
      };
      system.build = {
        kernel = payload;
        initrd = payload;
      };
    };
  };
  manifestFor = metadata: varProvisioning: let
    test = fleet.mkFleetTest {
      name = "provenance-input";
      timeout = 1;
      testScript = "";
      machines.machine = {inherit system metadata varProvisioning;};
    };
  in
    builtins.head (builtins.fromJSON (builtins.unsafeDiscardStringContext test.manifest.text)).machines;
in {
  nativeAssemblyTools = (disk {}).buildDeps == [
    buildPackages.e2fsprogs
    buildPackages.coreutils
    buildPackages.fakeroot
    buildPackages.jq
    buildPackages.util-linux
  ];
  architectureSpecificRootTypes =
    partitionType operator "root-a" == "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
    && partitionType operator "root-b" == partitionType operator "root-a"
    && partitionType (assembly {guestArchitecture = "aarch64";}) "root-a" == "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"
    && partitionType (assembly {guestArchitecture = "i686";}) "root-a" == "44479540-F297-41B2-9AF7-D131D5F0458A"
    && partitionType (assembly {guestArchitecture = "riscv64";}) "root-a" == "72EC70A6-CF74-40E6-BD49-4BDA08E8F224";
  unsupportedArchitectureRejected = !(builtins.tryEval (assembly {guestArchitecture = "unknown";})).success;
  protectedVarLabel =
    contains protected "-E root_selinux=system_u:object_r:aos_var_t:s0"
    && contains protected "ea_get / security.selinux"
    && contains protected "security.selinux (23) = \"system_u:object_r:aos_var_t:s0\""
    && !(contains operator "-E root_selinux=");
  bootTypeCannotMatchVar =
    builtins.all (script: partitionType script "boot" == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") [operator fallback uninitialized]
    && partitionType operator "var" == "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
    && partitionType fallback "var" == partitionType operator "var";
  bakedOperatorMarker = contains operator "name=aos-provenance-operator-v1" && !(contains operator "name=aos-provenance-fallback-v1");
  defaultFallbackMarker = contains fallback "name=aos-provenance-fallback-v1" && !(contains fallback "name=aos-provenance-operator-v1");
  repartRemainsUncommitted = !(contains uninitialized "name=aos-provenance-") && !(contains uninitialized "name=var");
  invalidBeforeDerivation =
    !(builtins.tryEval
      (disk {
        provisioningSource = "unknown";
      }).pname).success;
  invalidSourceRejected = !(builtins.tryEval (assembly {provisioningSource = "unknown";})).success;
  invalidRepartSourceRejected =
    !(builtins.tryEval (assembly {
      provisioningSource = "unknown";
      varProvisioning = "repart";
    })).success;
  fleetOperatorInput = (manifestFor {"host.nix" = "{}";} "baked").disk == "${payload}/operator-baked/disk.img";
  fleetFactsOnlyFallback =
    (manifestFor {
      "facts.json" = "{}";
      "host.nix.sig" = "signature";
    } "baked").disk
    == "${payload}/fallback-baked/disk.img";
  fleetEmptyFallback = (manifestFor {} "baked").disk == "${payload}/fallback-baked/disk.img";
  fleetUninitializedDisk = (manifestFor {"host.nix" = "{}";} "repart").disk == "${payload}/operator-repart/disk.img";
}
