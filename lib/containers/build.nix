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
  definitionAttribute,
}: let
  releaseIdentity =
    systemIdentity.release or {
      enabled = false;
      tier = "production";
      registry = "andyl/main";
      channel = "stable";
    };
  releaseOsMetadata = lib.optionalString releaseIdentity.enabled (
    lib.concatStringsSep "\n" [
      "AOS_RELEASE_TIER=${releaseIdentity.tier}"
      "AOS_REGISTRY=${releaseIdentity.registry}"
      "AOS_CHANNEL=${releaseIdentity.channel}"
      "AOS_REGISTRY_ROOT_EPOCH=${toString releaseIdentity.rootEpoch}"
    ]
    + "\n"
  );
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

  auditRoots = uniqueByPath (builtins.concatMap (layer: layer.roots) container.layers);
  runtimeAudit = import ../build/runtime-closure-audit.nix {
    inherit pkgs lib;
    name = "container-${container.name}";
    roots = auditRoots;
    inherit (container.budgets) maxClosureMiB maxDevelopmentPayloadMiB;
  };
  bakedRootInventory = pkgs.writeTextFile {
    name = "aos-container-${container.name}-baked-roots";
    text =
      builtins.concatStringsSep "\n" (map builtins.toString container.packageRoots)
      + "\n";
    destination = "/baked-roots";
  };
  configuredDirectoryPaths = map (directory: directory.path) container.filesystem.directories;
  configuredFilePaths = map (file: file.path) container.filesystem.files;
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
    ${releaseOsMetadata}
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
  referenceName = "${container.publication.repository}:${container.publication.referenceTag}";

  packageEvidence = import ./package-evidence.nix {
    inherit lib pkgs;
    overrides = container.publication.evidenceOverrides;
  };

  mkPlatformBuild = suffix: let
    suffixPart =
      if suffix == ""
      then ""
      else "-${suffix}";
    closureLayers =
      map
      (layer:
        oci.mkClosureLayer {
          pname = "aos-container-${container.name}-layer-${layer.name}${suffixPart}";
          layerName = layer.name;
          inherit (layer) roots subtractRoots;
        })
      container.layers;
    referenceGraph = oci.mkReferenceGraph {
      pname = "aos-container-${container.name}-runtime-reference-graph${suffixPart}";
      rootPaths = auditRoots;
    };
    facadeLayer = import ./facade-layer.nix {
      inherit lib pkgs oci referenceGraph;
      packageRoots = container.packageRoots;
      explicit = container.filesystem.facade;
      expectedCollisions = container.filesystem.allowedFacadeCollisions;
      pname = "aos-container-${container.name}-golden-facade${suffixPart}";
    };
    standardFiles = [
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
    reservedFilePaths = map (file: file.path) standardFiles;
    filePathCollisions = builtins.filter (path: builtins.elem path reservedFilePaths) configuredFilePaths;
    metadataFiles =
      if filePathCollisions == []
      then standardFiles ++ container.filesystem.files
      else throw "container filesystem files collide with reserved metadata paths: ${lib.concatStringsSep ", " filePathCollisions}";
    metadataLayer = oci.mkRootMetadataLayer {
      pname = "aos-container-${container.name}-root-metadata${suffixPart}";
      layerName = "root-metadata";
      directories = standardDirectories ++ container.filesystem.directories;
      files = metadataFiles;
      symlinks = compatibilitySymlinks;
      storeLayers = closureLayers;
    };
    image = oci.mkImageLayout {
      pname = "aos-container-${container.name}-${container.platform.architecture}${suffixPart}";
      layers = closureLayers ++ [facadeLayer metadataLayer];
      inherit runtimeAudit;
      platform = {
        inherit (container.platform) os architecture;
      };
      inherit referenceName;
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
      pname = "aos-container-${container.name}-${container.platform.architecture}-docker${suffixPart}";
      inherit image;
      references = [referenceName];
    };
    ociIndex = oci.mkMultiPlatformIndex {
      pname = "aos-container-${container.name}-${container.platform.architecture}-index${suffixPart}";
      images = [image];
      inherit referenceName;
      annotations = releaseAnnotations;
    };
    sourceGraph = oci.mkEvidenceSourceGraph {
      pname = "aos-container-${container.name}-source-reference-graph${suffixPart}";
      inherit referenceGraph;
      packageCatalog = packageEvidence.catalog;
      candidateSources = packageEvidence.sourcePaths;
    };
  in {
    inherit closureLayers referenceGraph facadeLayer metadataLayer image dockerArchive ociIndex sourceGraph;
  };
  primary = mkPlatformBuild "";
  repeat = mkPlatformBuild "repeat";

  mkEvidence = {
    pname,
    platformBuild,
  }:
    oci.mkEvidenceLayout {
      inherit pname;
      image = primary.ociIndex;
      inherit (platformBuild) referenceGraph sourceGraph closureLayers;
      packageCatalog = packageEvidence.catalog;
      inherit definitionAttribute;
      releaseIdentity = container.publication.releaseIdentity;
      packageName = pkgs.aos.pname;
      packageVersion = pkgs.aos.version;
      imageName = container.name;
    };
  evidence = mkEvidence {
    pname = "aos-container-${container.name}-evidence";
    platformBuild = primary;
  };
  evidenceRepeat = mkEvidence {
    pname = "aos-container-${container.name}-evidence-repeat";
    platformBuild = repeat;
  };
  publicationInputs = import ./publication-inputs.nix {
    inherit pkgs;
    pname = "aos-container-${container.name}-${container.platform.architecture}-publication-inputs";
    index = primary.ociIndex;
    evidenceLayout = evidence;
  };
  publicationInputsRepeat = import ./publication-inputs.nix {
    inherit pkgs;
    pname = "aos-container-${container.name}-${container.platform.architecture}-publication-inputs-repeat";
    index = repeat.ociIndex;
    evidenceLayout = evidenceRepeat;
  };
  reproducibility = pkgs.mkDerivation {
    pname = "aos-container-${container.name}-${container.platform.architecture}-reproducibility";
    version = "1";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.jq
      primary.image
      repeat.image
      primary.dockerArchive
      repeat.dockerArchive
      primary.ociIndex
      repeat.ociIndex
      evidence
      evidenceRepeat
      publicationInputs
      publicationInputsRepeat
    ];
    outputChecks.out = {};
    unsafeDiscardReferences.out = true;
    phases = [
      {
        name = "qualify";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"

          diff -r ${primary.image} ${repeat.image}
          cmp ${primary.image}/image.oci.tar ${repeat.image}/image.oci.tar
          diff -r ${primary.dockerArchive} ${repeat.dockerArchive}
          cmp ${primary.dockerArchive}/image.docker.tar ${repeat.dockerArchive}/image.docker.tar
          diff -r ${primary.ociIndex} ${repeat.ociIndex}
          cmp ${primary.ociIndex}/image.oci.tar ${repeat.ociIndex}/image.oci.tar
          diff -r ${evidence} ${evidenceRepeat}
          cmp ${evidence}/evidence.oci.tar ${evidenceRepeat}/evidence.oci.tar
          diff -r ${publicationInputs} ${publicationInputsRepeat}

          jq -S -n \
            --arg schema 'aos.container.production-reproducibility/v1' \
            --arg system ${lib.escapeShellArg container.platform.aosSystem} \
            --arg architecture ${lib.escapeShellArg container.platform.architecture} \
            --arg ociArchiveSha256 "$(sha256sum ${primary.image}/image.oci.tar | cut -d ' ' -f 1)" \
            --arg dockerArchiveSha256 "$(sha256sum ${primary.dockerArchive}/image.docker.tar | cut -d ' ' -f 1)" \
            --arg indexSha256 "$(sha256sum ${primary.ociIndex}/image-index.json | cut -d ' ' -f 1)" \
            --arg evidenceArchiveSha256 "$(sha256sum ${evidence}/evidence.oci.tar | cut -d ' ' -f 1)" \
            '{
              schema: $schema,
              platform: {aosSystem: $system, architecture: $architecture},
              comparisons: {
                ociLayoutAndArchive: true,
                dockerArchive: true,
                index: true,
                evidence: true
              },
              sha256: {
                ociArchive: $ociArchiveSha256,
                dockerArchive: $dockerArchiveSha256,
                index: $indexSha256,
                evidenceArchive: $evidenceArchiveSha256
              }
            }' > "$out/evidence.json"
        '';
      }
    ];
    meta.description = "Independent production container byte reproducibility for ${container.platform.aosSystem}";
  };

  metadataSpec = {
    schema = "aos.container.definition/v1";
    inherit (container) name;
    annotations = releaseAnnotations;
    inherit (container) platform runtime packageManagement budgets;
    publication = {
      inherit (container.publication) repository releaseIdentity referenceTag;
    };
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
  definition = metadataSpec;
  platforms.${container.platform.aosSystem} = {
    ociLayout = primary.image;
    ociArchive = primary.image;
    dockerArchive = primary.dockerArchive;
    image = primary.image;
    inherit metadata evidence;
    inherit publicationInputs;
  };
  ociIndex = primary.ociIndex;
  inherit evidence publicationInputs;
  qualification = {
    primaryImage = primary.image;
    repeatImage = repeat.image;
    primaryDockerArchive = primary.dockerArchive;
    repeatDockerArchive = repeat.dockerArchive;
    primaryIndex = primary.ociIndex;
    repeatIndex = repeat.ociIndex;
    inherit evidence evidenceRepeat publicationInputs publicationInputsRepeat reproducibility;
    evidenceInputs = {
      inherit auditRoots;
      primaryClosureLayers = primary.closureLayers;
      repeatClosureLayers = repeat.closureLayers;
      packageCatalog = packageEvidence.catalog;
      candidateSources = packageEvidence.sourcePaths;
    };
  };
  coordination = {
    inherit (container) name;
    inherit (container.publication) repository releaseIdentity referenceTag;
    inherit (container.platform) aosSystem os architecture;
    packageName = pkgs.aos.pname;
    packageVersion = pkgs.aos.version;
    inherit definitionAttribute;
    indexAnnotations = builtins.removeAttrs releaseAnnotations ["dev.andyl.aos.system"];
  };
  checks = {
    inherit runtimeAudit evidence evidenceRepeat reproducibility;
    referenceGraph = primary.referenceGraph;
    sourceGraph = primary.sourceGraph;
    facadeLayer = primary.facadeLayer;
    metadataLayer = primary.metadataLayer;
  };
}
