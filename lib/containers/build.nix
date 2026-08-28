##! lib/containers/build.nix — Typed container definition assembler
##!
##! Converts one evaluated container definition into deterministic closure
##! layers, scratch metadata, a platform OCI layout/archive, a Docker-load
##! archive, and a single-platform index. Multi-target flake composition can
##! combine the independently built platform images without repacking layers.
{
  lib,
  pkgs,
  oci,
  container,
  systemIdentity,
}: let
  uniqueByPath = values: let
    step = state: value: let
      path = builtins.unsafeDiscardStringContext (builtins.toString value);
    in
      if builtins.elem path state.seen
      then state
      else {
        seen = state.seen ++ [path];
        result = state.result ++ [value];
      };
  in
    (builtins.foldl' step {
        seen = [];
        result = [];
      }
      values).result;

  closureLayers =
    map
    (layer:
      oci.mkClosureLayer {
        pname = "aos-container-${container.name}-layer-${layer.name}";
        layerName = layer.name;
        inherit (layer) roots subtractRoots;
      })
    container.layers;

  auditRoots = uniqueByPath (builtins.concatMap (layer: layer.roots) container.layers);
  runtimeAudit = import ../build/runtime-closure-audit.nix {
    inherit pkgs lib;
    name = "container-${container.name}";
    roots = auditRoots;
    inherit (container.budgets) maxClosureMiB maxDevelopmentPayloadMiB;
  };
  referenceGraph = oci.mkReferenceGraph {
    pname = "aos-container-${container.name}-runtime-reference-graph";
    rootPaths = auditRoots;
  };
  bakedRootInventory = pkgs.writeTextFile {
    name = "aos-container-${container.name}-baked-roots";
    text =
      builtins.concatStringsSep "\n" (map builtins.toString container.packageRoots)
      + "\n";
    destination = "/baked-roots";
  };
  facadeLayer = import ./facade-layer.nix {
    inherit lib pkgs oci referenceGraph;
    packageRoots = container.packageRoots;
    explicit = container.filesystem.facade;
    expectedCollisions = container.filesystem.allowedFacadeCollisions;
    pname = "aos-container-${container.name}-golden-facade";
  };

  configuredDirectoryPaths = map (directory: directory.path) container.filesystem.directories;
  standardDirectories =
    builtins.filter
    (directory: !builtins.elem directory.path configuredDirectoryPaths)
    [
      {
        path = "/bin";
        mode = "0755";
      }
      {
        path = "/etc";
        mode = "0755";
      }
      {
        path = "/etc/nix";
        mode = "0755";
      }
      {
        path = "/etc/pki";
        mode = "0755";
      }
      {
        path = "/etc/pki/tls";
        mode = "0755";
      }
      {
        path = "/etc/pki/tls/certs";
        mode = "0755";
      }
      {
        path = "/etc/ssl";
        mode = "0755";
      }
      {
        path = "/etc/ssl/certs";
        mode = "0755";
      }
      {
        path = "/lib";
        mode = "0755";
      }
      {
        path = "/nix";
        mode = "0755";
      }
      {
        path = "/nix/store";
        mode = "0755";
      }
      {
        path = "/nix/var";
        mode = "0755";
      }
      {
        path = "/nix/var/nix";
        mode = "0755";
      }
      {
        path = "/nix/var/nix/gcroots";
        mode = "0755";
      }
      {
        path = "/nix/var/nix/gcroots/aos-profiles";
        mode = "0755";
      }
      {
        path = "/nix/var/nix/profiles";
        mode = "0755";
      }
      {
        path = "/usr";
        mode = "0755";
      }
      {
        path = "/usr/bin";
        mode = "0755";
      }
      {
        path = "/usr/lib";
        mode = "0755";
      }
      {
        path = "/usr/sbin";
        mode = "0755";
      }
      {
        path = "/var";
        mode = "0755";
      }
      {
        path = "/var/cache";
        mode = "0755";
      }
      {
        path = "/var/lib";
        mode = "0755";
      }
    ];

  compatibilitySymlinks =
    [
      {
        path = "/etc/ssl/certs/ca-certificates.crt";
        target = "${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt";
      }
      {
        path = "/etc/ssl/certs/ca-bundle.crt";
        target = "${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt";
      }
      {
        path = "/etc/pki/tls/certs/ca-bundle.crt";
        target = "${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt";
      }
      {
        path = "/var/lib/profiles";
        target = "/nix/var/nix/gcroots/aos-profiles";
      }
    ]
    ++ lib.optional container.filesystem.shell {
      path = "/bin/sh";
      target = "${pkgs.bash}/bin/bash";
      requireExecutable = true;
    };

  initScript = import ./init-script.nix {
    inherit lib pkgs;
    defaultCommand = container.runtime.command;
  };
  initSource = pkgs.writeTextFile {
    name = "aos-container-${container.name}-init";
    text = initScript;
    destination = "/init";
    executable = true;
  };
  osRelease = ''
    NAME="${systemIdentity.name}"
    ID=aos
    VERSION="${systemIdentity.version}"
    VERSION_ID=${systemIdentity.version}
    PRETTY_NAME="${systemIdentity.name} ${systemIdentity.version}"
    HOME_URL="https://aos.dev"
    BUG_REPORT_URL="https://aos.dev/issues"
    AOS_CONTAINER=1
    AOS_SYSTEM=${container.platform.aosSystem}
    AOS_STATE_VERSION=${systemIdentity.stateVersion}
    AOS_MODULE_ABI=${toString systemIdentity.moduleAbi}
  '';
  releaseAnnotations =
    container.annotations
    // {
      "org.opencontainers.image.version" = systemIdentity.version;
      "dev.andyl.aos.release.name" = systemIdentity.name;
      "dev.andyl.aos.release.version" = systemIdentity.version;
      "dev.andyl.aos.state-version" = systemIdentity.stateVersion;
      "dev.andyl.aos.module-abi" = toString systemIdentity.moduleAbi;
    };

  metadataLayer = oci.mkRootMetadataLayer {
    pname = "aos-container-${container.name}-root-metadata";
    layerName = "root-metadata";
    directories = standardDirectories ++ container.filesystem.directories;
    files = [
      {
        path = "/etc/group";
        mode = "0644";
        text = "root:x:0:\n";
      }
      {
        path = "/etc/nix/nix.conf";
        mode = "0644";
        text = ''
          build-users-group =
          experimental-features = nix-command
          sandbox = false
          substituters =
        '';
      }
      {
        path = "/etc/os-release";
        mode = "0644";
        text = osRelease;
      }
      {
        path = "/etc/passwd";
        mode = "0644";
        text = "root:x:0:0:root:/root:/usr/bin/sh\n";
      }
      {
        path = "/etc/shadow";
        mode = "0600";
        text = "root:!:1::::::\n";
      }
      {
        path = "/aos-registration";
        mode = "0444";
        source = "${referenceGraph}/registration";
      }
      {
        path = "/nix/var/nix/.aos-container-init.lock";
        mode = "0600";
        text = "";
      }
      {
        path = "/usr/lib/aos-container/baked-roots";
        mode = "0444";
        source = "${bakedRootInventory}/baked-roots";
      }
      {
        path = "/usr/lib/aos-container/store-paths";
        mode = "0444";
        source = "${referenceGraph}/store-paths";
      }
      {
        path = "/usr/bin/aos-container-init";
        mode = "0555";
        source = "${initSource}/init";
      }
    ];
    symlinks = compatibilitySymlinks;
    storeLayers = closureLayers;
  };

  image = oci.mkImageLayout {
    pname = "aos-container-${container.name}-${container.platform.architecture}";
    layers = closureLayers ++ [facadeLayer metadataLayer];
    inherit runtimeAudit;
    platform = {
      inherit (container.platform) os architecture;
    };
    referenceName = "${container.publication.repository}:latest";
    annotations = releaseAnnotations;
    indexAnnotations = releaseAnnotations;
    config = {
      entrypoint = container.runtime.entrypoint;
      cmd = container.runtime.command;
      env = container.runtime.environment;
      user = container.runtime.user;
      workingDir = container.runtime.workingDirectory;
      stopSignal = container.runtime.stopSignal;
      labels = releaseAnnotations;
    };
  };
  dockerArchive = oci.mkDockerArchive {
    pname = "aos-container-${container.name}-${container.platform.architecture}-docker";
    inherit image;
    references = ["${container.publication.repository}:latest"];
  };
  ociIndex = oci.mkMultiPlatformIndex {
    pname = "aos-container-${container.name}-${container.platform.architecture}-index";
    images = [image];
    referenceName = "${container.publication.repository}:latest";
    annotations = releaseAnnotations;
  };

  metadataSpec = {
    schema = "aos.container.definition/v1";
    inherit (container) name;
    annotations = releaseAnnotations;
    inherit (container) platform runtime publication packageManagement budgets;
    packageRoots = map builtins.toString container.packageRoots;
    layers =
      map (layer: {
        inherit (layer) name;
        roots = map builtins.toString layer.roots;
        subtractRoots = map builtins.toString layer.subtractRoots;
      })
      container.layers;
  };
  metadata = pkgs.mkDerivation {
    pname = "aos-container-${container.name}-metadata";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.jq];
    outputChecks.out = {};
    inherit metadataSpec;
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "assemble";
        script = ''
          mkdir -p "$out"
          jq -cS .metadataSpec "$NIX_ATTRS_JSON_FILE" > "$out/definition.with-newline.json"
          size=$(stat -c %s "$out/definition.with-newline.json")
          truncate -s "$((size - 1))" "$out/definition.with-newline.json"
          mv "$out/definition.with-newline.json" "$out/definition.json"
        '';
      }
    ];
    meta.description = "Evaluated metadata for the ${container.name} AOS container";
  };
in {
  config = container;
  platforms.${container.platform.aosSystem} = {
    ociLayout = image;
    ociArchive = image;
    inherit dockerArchive metadata image;
  };
  inherit ociIndex;
  checks = {
    inherit runtimeAudit referenceGraph facadeLayer metadataLayer;
  };
}
