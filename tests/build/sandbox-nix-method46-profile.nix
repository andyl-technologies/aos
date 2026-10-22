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
  sandbox = cfg.aos.sandbox;
  controller = cfg.systemd.services.aos-sandboxd.serviceConfig;
  profile = sandbox.nixBroker._controllerProfile;
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
  validation = assert builtins.all (check: check.assertion) cfg.assertions;
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
      ${pkgs.python3}/bin/python3 - ${profile}/controller.json ${unit} <<'PY'
      import hashlib
      import json
      import pathlib
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
      PY
      mkdir -p "$out"
      printf '%s\n' 'PASS: combined immutable startup contract; no runtime floor authority' > "$out/result"
    ''
