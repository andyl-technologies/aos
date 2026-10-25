# Builds the combined installation's measured startup contract, without floors.
{
  lib,
  pkgs,
  systems,
}: let
  funded = import ../fleet/_sandbox-funded-system.nix {
    inherit lib pkgs systems;
    includeLifecycleReservations = true;
  };
  system = funded.extendModules {
    modules = [
      {
        aos.sandbox.controllerService.method46TpmFloor = {
          required = true;
          provisionCredential = "qualification-controller-method46-public";
          indexAuthCredential = "qualification-controller-method46-auth";
        };
        aos.sandbox.storageBroker.method46TpmFloor = {
          required = true;
          provisionCredential = "qualification-storage-method46-public";
          indexAuthCredential = "qualification-storage-method46-auth";
        };
      }
    ];
  };
  cfg = system.config;
  hostDescriptor = cfg.system.build.hostDeploymentBundle.nativeEvaluationDescriptor;
  hostInputs = hostDescriptor.nativeEvaluationInputs;
  hostReplay = lib.evalPackageModules {
    inherit (hostInputs) packages scope;
    operatorModules = hostInputs.configuration;
    runtimeModules = hostInputs.runtimeConfiguration;
    evaluationInput = hostDescriptor;
  };
  replayedServices = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
    inherit lib pkgs;
    inherit (hostReplay) config;
  };
  sandbox = cfg.aos.sandbox;
  controller = cfg.systemd.services.aos-sandboxd.serviceConfig;
  profile = sandbox.nixBroker._controllerProfile;
  viewRoots = cfg.systemd.services.aos-sandbox-view-roots.serviceConfig;
  viewService = cfg.systemd.services.aos-sandbox-cache-journal-view;
  parent = sandbox.resourceBank.parentEnclosure;
  root = cfg.systemd.services.aos-sandbox-policy-authorityd.serviceConfig;
  recovery = cfg.systemd.services.aos-sandbox-policy-cache-recovery;
  wrongPackage = system.extendModules {
    modules = [
      ({lib, ...}: {
        aos.sandbox.controllerService.package = lib.mkForce pkgs.coreutils;
      })
    ];
  };
  missingAuth = system.extendModules {
    modules = [
      ({lib, ...}: {
        aos.sandbox.controllerService.method46TpmFloor.indexAuthCredential = lib.mkForce null;
      })
    ];
  };
  rejectedBy = message: selected:
    builtins.any (check: check.message == message && !check.assertion) selected.config.assertions;
  failedAssertions = builtins.filter (check: !check.assertion) cfg.assertions;
  validation = assert failedAssertions
  == []
  || throw (
    builtins.concatStringsSep "\n" (builtins.map (check: check.message) failedAssertions)
  );
  # Compare the actual independently replayed input, including its owner and
  # deferred unit addresses, with the image that native activation must adopt.
  assert hostReplay.config.aos.servicesRetainImageDefinitions;
  assert replayedServices."ssh.aos-ssh-ready" == cfg.system.build.systemdBootstrapServices."ssh.aos-ssh-ready";
  assert viewRoots.ExecStart == "/usr/lib/systemd/aos-selinux-root-handoff --launch-runtime-roots ${cfg.aos.security.selinux._runtimeRootsProvisioner}/bin/aos-selinux-runtime-roots --root / --prepare-sandbox-view-roots";
  assert viewRoots.Slice == "aoscomponents.slice";
  assert viewRoots.LimitNOFILE == parent.fixedOpenFilesPerProcess;
  assert viewRoots.MemoryMax == parent.fixedServices.memory-bytes;
  assert viewRoots.TasksMax == parent.fixedServices.pids;
  assert !(viewRoots.PermissionsStartOnly or false);
  assert !(viewRoots.NoNewPrivileges);
  assert viewRoots.CapabilityBoundingSet == ["CAP_CHOWN" "CAP_DAC_OVERRIDE" "CAP_DAC_READ_SEARCH" "CAP_SYS_ADMIN"];
  assert (viewService.serviceConfig.ExecStartPre or []) == [];
  assert builtins.elem "aos-sandbox-view-roots.service" viewService.requires;
  assert builtins.elem "aos-sandbox-view-roots.service" viewService.after;
  assert (root.StateDirectory or []) == [];
  assert builtins.elem "/var/lib/aos/sandbox/policy-compiler" root.ReadWritePaths;
  assert (recovery.serviceConfig.StateDirectory or []) == [];
  assert (recovery.serviceConfig.ReadWritePaths or []) == [];
  assert recovery.serviceConfig.ProtectSystem == "strict";
  assert recovery.serviceConfig.SELinuxContext == "system_u:system_r:aos_sandbox_policy_recovery_t";
  assert recovery.serviceConfig.NoNewPrivileges;
  assert (recovery.requires or []) == [];
  assert (recovery.wants or []) == [];
  assert builtins.elem "aos-sandbox-view-roots.service" recovery.after;
  assert sandbox.controllerService.package == sandbox.nixBroker._package;
  assert sandbox.policyAuthority.package == sandbox.nixBroker._package;
  assert builtins.elem "/proc/1/exe:aos-method46-pid1-image:read-only" controller.OpenFile;
  assert builtins.elem "/proc/1/exe:aos-nix-controller-pid1-image:read-only" controller.OpenFile;
  assert builtins.length controller.OpenFile == 4;
  assert rejectedBy "required Controller TPM floor requires immutable enforcing SELinux and the exact AOS package; owner IDs are independently compiled from the immutable module assignment" wrongPackage;
  assert rejectedBy "method46TpmFloor requires distinct external public/auth credentials in required mode, or neither in permanently closed legacy mode" missingAuth; true;
  unit = pkgs.writeTextFile {
    name = "sandbox-nix-method46-controller-unit";
    text = cfg.systemd.units."aos-sandboxd.service".text;
  };
in
  assert validation;
    pkgs.runCommand "sandbox-nix-method46-profile-check" {
      buildDeps = [pkgs.python3];
    } ''
      ${pkgs.python3}/bin/python3 - ${profile}/controller.json ${unit} ${sandbox.resourceBank._parentImage}/enclosure.bin <<'PY'
      import hashlib
      import json
      import pathlib
      import struct
      import sys

      profile_path = pathlib.Path(sys.argv[1])
      profile = json.loads(profile_path.read_bytes())
      unit = pathlib.Path(sys.argv[2]).read_bytes()
      original = (
          f"OpenFile={profile_path}:aos-nix-controller-profile:read-only\n"
      ).encode()
      assert unit.splitlines(keepends=True).count(original) == 1
      measured = unit.replace(
          original, b"OpenFile=@AOS_NIX_PROFILE@:aos-nix-controller-profile:read-only\n"
      )
      assert measured.count(b"OpenFile=/proc/1/exe:aos-method46-pid1-image:read-only\n") == 1
      assert measured.count(b"OpenFile=/proc/1/exe:aos-nix-controller-pid1-image:read-only\n") == 1
      declared_digest = bytes(profile["unit_sha256"])
      installed_digest = hashlib.sha256(measured).digest()
      assert declared_digest == installed_digest, (
          "Controller startup contract differs from the installed unit: "
          f"profile={declared_digest.hex()} installed={installed_digest.hex()}"
      )
      assert profile["role"] == "controller"

      # Inspect the actual finite manifest consumed by the original manager.
      enclosure = pathlib.Path(sys.argv[3]).read_bytes()
      assert enclosure[:8] == b"AOSRPE06"
      assert hashlib.sha256(enclosure[:-32]).digest() == enclosure[-32:]
      count, = struct.unpack_from(">H", enclosure, 452)
      assert 1 <= count <= 18
      assert len(enclosure) == 3478 + count * 1506
      names = [
          enclosure[3446 + index * 1506:3510 + index * 1506].split(b"\0", 1)[0]
          for index in range(count)
      ]
      assert names == sorted(set(names))
      assert names.count(b"aos-sandbox-view-roots.service") == 1
      PY
      mkdir -p "$out"
      printf '%s\n' 'PASS: combined immutable startup contract; no runtime floor authority' > "$out/result"
    ''
