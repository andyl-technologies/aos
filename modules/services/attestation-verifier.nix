##! modules/services/attestation-verifier.nix — Fleet attestation verifier role.
##!
##! Defines the standalone verifier host role for RFC-0001 package
##! attestation. The service consumes verifier-delivered evidence from local
##! files, runs the AOS `apm attest verify` verifier, and writes an atomic JSON
##! result. It is deliberately separate from registry publication services: it
##! reads public registry/catalog evidence and quote bundles, but never handles
##! registry signing keys.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.attestationVerifier;
  absolutePathType = lib.types.strMatching "/.*";
  optionalAbsolutePathType = lib.types.nullOr absolutePathType;
  shellArg = lib.escapeShellArg;
  appendArgs =
    lib.concatMapStrings
    (arg: ''
      set -- "$@" ${arg.flag} ${shellArg arg.path}
    '');
  quoteIdentityArgs = appendArgs (
    builtins.map (path: {
      flag = "--quote-identity-file";
      inherit path;
    })
    cfg.quoteIdentityFiles
  );
  catalogArgs = appendArgs (
    builtins.map (path: {
      flag = "--catalog-file";
      inherit path;
    })
    cfg.catalogFiles
  );
  baselineArg = lib.optionalString (cfg.pcr15BaselineFile != null) ''
    if [ ! -s ${shellArg cfg.pcr15BaselineFile} ]; then
      echo "package attestation baseline file is not ready: ${cfg.pcr15BaselineFile}" >&2
      exit 2
    fi
    baseline_pcr15="$(${pkgs.coreutils}/bin/cat -- ${shellArg cfg.pcr15BaselineFile})"
    set -- "$@" --pcr15-baseline "$baseline_pcr15"
  '';
in {
  options.aos.services.attestationVerifier = {
    enable = lib.mkEnableOption "standalone AOS package attestation verifier service";

    eventLog = lib.mkOption {
      type = absolutePathType;
      default = "/var/lib/aos-attestation-verifier/aos-packages.cel";
      description = ''
        Absolute path to the package attestation event log supplied to
        the verifier service.
      '';
    };

    quoteDir = lib.mkOption {
      type = absolutePathType;
      default = "/var/lib/aos-attestation-verifier/quote";
      description = ''
        Absolute path to the verifier-local quote bundle directory.
      '';
    };

    nonceFile = lib.mkOption {
      type = absolutePathType;
      default = "/var/lib/aos-attestation-verifier/nonce";
      description = ''
        Absolute path to a file containing the verifier nonce as hex.
      '';
    };

    resultFile = lib.mkOption {
      type = absolutePathType;
      default = "/var/lib/aos-attestation-verifier/result.json";
      description = ''
        Absolute path where the verifier writes its JSON result.
      '';
    };

    pcr15BaselineFile = lib.mkOption {
      type = optionalAbsolutePathType;
      default = null;
      description = ''
        Optional absolute path to a file containing the expected PCR 15
        baseline before package measurements.
      '';
    };

    quoteIdentityFiles = lib.mkOption {
      type = lib.types.listOf absolutePathType;
      default = [];
      description = ''
        Quote identity pin catalogs required by the verifier.
      '';
    };

    catalogFiles = lib.mkOption {
      type = lib.types.listOf absolutePathType;
      default = [];
      description = ''
        Additional golden package measurement catalogs required by the
        verifier.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.aos-attestation-verifier = {
      description = "Verify AOS package attestation evidence";
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        StateDirectory = "aos-attestation-verifier";
        StateDirectoryMode = "0750";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        RestrictAddressFamilies = "AF_UNIX";
        RestrictNamespaces = true;
        MemoryDenyWriteExecute = true;
        SystemCallFilter = "@system-service";
        SystemCallErrorNumber = "EPERM";
      };
      script = ''
        set -eu

        result_file=${shellArg cfg.resultFile}
        result_tmp="$result_file.tmp"

        ${pkgs.coreutils}/bin/rm -f -- "$result_tmp"
        set -- --json attest verify --system \
          --event-log ${shellArg cfg.eventLog} \
          --quote-dir ${shellArg cfg.quoteDir} \
          --nonce-file ${shellArg cfg.nonceFile}
        ${quoteIdentityArgs}
        ${catalogArgs}
        ${baselineArg}
        ${pkgs.aos}/bin/apm "$@" > "$result_tmp"
        ${pkgs.coreutils}/bin/mv -f -- "$result_tmp" "$result_file"
      '';
    };
  };
}
