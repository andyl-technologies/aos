# The report route is specified but cannot be enabled without sender custody.
{
  pkgs,
  lib,
}: let
  unitOptions = {lib, ...}: {
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.systemd.services = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.systemd.sockets = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.aos.sandbox.storageBroker.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    options.aos.sandbox.storageBroker.kernelExportStageSignerCredential = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    options.aos.sandbox.networkWorker.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
  };
  base = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      unitOptions
      ../../modules/sandbox/kernel-export-owner.nix
      {
        aos.sandbox.kernelExportOwner = {
          enable = true;
          leaseVerifierCredential = "lease-test";
          stageVerifierCredential = "stage-test";
        };
      }
    ];
  };
  requested = base.extendModules {
    modules = [{
      aos.sandbox.kernelExportOwner.reportIngress = {
        enable = true;
        handoffCredential = "handoff-test";
      };
    }];
  };
  missingHandoff = base.extendModules {
    modules = [{aos.sandbox.kernelExportOwner.reportIngress.enable = true;}];
  };
  unavailable = check:
    check.message
    == "kernelExportOwner report ingress remains unavailable until an exact reporter descriptor-origin sender and enforcing MAC/socket custody are deployed";
  needsHandoff = check:
    check.message == "kernelExportOwner report ingress requires an external handoff comparison credential";
  reportSocket = requested.config.systemd.sockets.aos-sandbox-kernel-export-owner-prepared-report;
  reportService = requested.config.systemd.services.aos-sandbox-kernel-export-owner-report-ingressd;
in
  assert !(base.config.systemd.sockets ? aos-sandbox-kernel-export-owner-prepared-report);
  assert !(base.config.systemd.services ? aos-sandbox-kernel-export-owner-report-ingressd);
  assert lib.any (check: !check.assertion) (lib.filter unavailable requested.config.assertions);
  assert lib.any (check: !check.assertion) (lib.filter needsHandoff missingHandoff.config.assertions);
  assert reportSocket.socketConfig.ListenSequentialPacket == "/run/aos/kernel-export-owner/prepared-report.sock";
  assert reportSocket.socketConfig.PassCredentials && reportSocket.socketConfig.PassPIDFD;
  assert reportSocket.socketConfig.SocketMode == "0600";
  assert reportService.serviceConfig.CapabilityBoundingSet == "";
  assert reportService.serviceConfig.ExecStart == "${pkgs.aos-sandbox-kernel-export-ownerd}/bin/aos-sandbox-kernel-export-owner-report-ingressd ${pkgs.aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  assert reportService.serviceConfig.LoadCredential == [
    "kernel-export-report-handoff-v1:/run/credentials/@system/handoff-test"
  ];
    pkgs.mkDerivation {
      pname = "sandbox-kernel-report-ingress-contract";
      version = "0";
      src = null;
      buildDeps = [];
      runtimeDeps = [];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
