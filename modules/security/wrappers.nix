##! modules/security/wrappers.nix — Runtime privilege wrappers
##!
##! Requests exact package executables as typed runtime filesystem entries.
##! Package outputs remain immutable and never carry privileged mode bits;
##! the selected filesystem provider owns materialization and observation.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.wrappers;
  names = builtins.attrNames cfg;

  serviceManagement = lib.abilities.interfaces.serviceManagement;
  filesystemEntry = serviceManagement.interfaces.filesystemEntry;

  wrapperRoot = "/run/wrappers";
  wrapperBin = "${wrapperRoot}/bin";
  consumerInstance = "system:security-wrappers";

  wrapperRootRequest = "security-wrappers";
  wrapperBinRequest = "security-wrapper-bin";
  retainedBy = request: lib.abilities.resultOf request "retained-resource";
  directory = key: name: destination: prerequisites: {
    inherit key;
    parameters = {
      inherit name destination prerequisites;
      entry.kind = "directory";
      owner = "root";
      group = "root";
      mode = "0755";
    };
  };
  wrapperRequest = name: let
    wrapper = cfg.${name};
  in {
    key = "security-wrapper-${name}";
    parameters = {
      inherit name;
      entry = {
        kind = "copied-file";
        source = {
          kind = "artifact-file";
          reference = wrapper.source;
        };
        maximum_size_bytes = wrapper.maximumSizeBytes;
      };
      destination = "${wrapperBin}/${name}";
      prerequisites = [(retainedBy wrapperBinRequest)];
      inherit (wrapper) owner group mode;
    };
  };
  filesystemRequests = serviceManagement.forProducers {
    inherit consumerInstance;
    interface = filesystemEntry;
    methods = ["materialize" "observe" "release"];
    producers =
      [
        (directory wrapperRootRequest "wrappers" wrapperRoot [])
        (directory wrapperBinRequest "wrapper-bin" wrapperBin [(retainedBy wrapperRootRequest)])
      ]
      ++ builtins.map wrapperRequest names;
  };
in {
  options.aos.security.wrappers = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        source = lib.mkOption {
          type = lib.abilities.types.artifactPathReference;
          description = "Exact package artifact and relative executable path copied into the runtime wrapper directory.";
        };
        owner = lib.mkOption {
          type = lib.abilities.types.deferredResult lib.abilities.types.principalName;
          default = "root";
          description = "Owner of the runtime wrapper.";
        };
        group = lib.mkOption {
          type = lib.abilities.types.deferredResult lib.abilities.types.groupName;
          default = "root";
          description = "Group of the runtime wrapper.";
        };
        mode = lib.mkOption {
          type = lib.abilities.types.fileMode;
          default = "4755";
          description = "Four-digit octal mode applied to the runtime wrapper.";
        };
        maximumSizeBytes = lib.mkOption {
          type = lib.types.addCheck lib.types.int (
            value: value >= 1 && value <= lib.abilities.types.limits.maxSafeInteger
          );
          default = lib.abilities.types.limits.maxSafeInteger;
          description = "Maximum source file size accepted while materializing the runtime wrapper.";
        };
      };
    });
    default = {};
    description = "Privileged executables materialized under ${wrapperBin}.";
  };

  config = lib.mkIf (names != []) (lib.mkMerge [
    {
      assertions =
        builtins.map
        (name: {
          assertion = builtins.match "[A-Za-z0-9._+-]+" name != null;
          message = "aos.security.wrappers names may contain only letters, digits, '.', '_', '+', and '-'";
        })
        names;

      aos.abilities.instances.${consumerInstance} = {};
    }
    {aos.abilities = filesystemRequests;}
  ]);
}
