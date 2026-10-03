##! Original image comparisons for the disabled manual offline Nix unit.
{
  mkDerivation,
  buildPackages,
  aos-sandboxd,
  systemd,
  aos-selinux-production-policy,
  aos-selinux-kernel-policy-readback,
  aos-nix-offline-tpm-helper,
  unitContract,
  hardware ? false,
}: let
  support = ./_aos-selinux-production-policy;
  sourcePolicy = "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
in
  mkDerivation {
    pname = "aos-nix-offline-startup-profile";
    version = "3";
    src = ./aos-normal-root-profile.py;
    buildDeps = [buildPackages.python3 buildPackages.patchelf buildPackages.binutils buildPackages.setools];
    runtimeDeps = [];
    propagatedDeps = [];
    outputChecks = {};
    inherit unitContract;
    hardwareMode = if hardware then "1" else "0";
    offlineHelper = if hardware then "${aos-nix-offline-tpm-helper}/libexec/aos-nix-offline-tpm-helper" else "";
    passAsFile = ["unitContract"];
    exportReferencesGraph.offlinePrepareRuntimeClosure = [aos-sandboxd]
      ++ (if hardware then [aos-nix-offline-tpm-helper] else []);
    nukeRefsKeep = [aos-sandboxd systemd aos-selinux-production-policy aos-selinux-kernel-policy-readback]
      ++ (if hardware then [aos-nix-offline-tpm-helper] else []);

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          export PYTHONPATH=${buildPackages.setools}/lib/python3/site-packages
          ${buildPackages.python3}/bin/python3 -B ${support}/effective_policy.py \
            ${sourcePolicy} > effective-policy.tsv
          test -s effective-policy.tsv
          mkdir -p "$out"
          install -m 0444 effective-policy.tsv "$out/effective-policy.tsv"
          install -m 0444 ${sourcePolicy} "$out/source-policy.33"

          # Import the sole existing image/ELF/closure primitives. This closed
          # producer changes only the purpose schema and selected unit contract.
          ${buildPackages.python3}/bin/python3 -B - \
            "$src" ${./aos-selinux-runtime-manifest.py} "$NIX_ATTRS_JSON_FILE" \
            ${aos-sandboxd}/bin/aos-sandbox-nix-floor-provision \
            ${systemd}/lib/systemd/systemd \
            ${aos-selinux-kernel-policy-readback}/policy.33 \
            "$out/source-policy.33" "$out/effective-policy.tsv" \
            "$unitContractPath" ${buildPackages.patchelf}/bin/patchelf \
            ${buildPackages.binutils}/bin/readelf "$out/profile.json" <<'PY'
          import hashlib
          import importlib.util
          import json
          import os
          import sys
          from pathlib import Path

          (source, helper_path, attrs, executable, pid1, canonical, source_policy,
           matrix, unit_path, patchelf, readelf, output) = map(Path, sys.argv[1:])
          spec = importlib.util.spec_from_file_location("aos_original_image_primitives", source)
          if spec is None or spec.loader is None:
              raise ValueError("original image primitives cannot be imported")
          original = importlib.util.module_from_spec(spec)
          spec.loader.exec_module(original)
          helpers = original.load_runtime_helpers(helper_path)
          paths = helpers.graph_paths(attrs, "offlinePrepareRuntimeClosure")
          helpers.validate_symlinks(paths)
          if helpers.closure_owner(str(executable), {str(path) for path in paths}) is None:
              raise ValueError("offline executable is outside the actual retained closure")
          loader, files = original.runtime_files(helpers, paths, executable, patchelf, readelf)

          hardware_profile = None
          if os.environ["hardwareMode"] == "1":
              helper = Path(os.environ["offlineHelper"])
              if helpers.closure_owner(str(helper), {str(path) for path in paths}) is None:
                  raise ValueError("offline helper is outside the actual retained closure")
              helper_loader, helper_files = original.runtime_files(
                  helpers, paths, helper, patchelf, readelf)
              members = {entry["path"]: entry for entry in files}
              for entry in helper_files:
                  prior = members.get(entry["path"])
                  if prior is not None and prior != entry:
                      raise ValueError("offline helper closure pins disagree")
                  members[entry["path"]] = entry
              files = [members[path] for path in sorted(members)]
              contract = helper.with_suffix(".contract").read_bytes()
              if len(contract) == 0 or len(contract) > 65536:
                  raise ValueError("offline compiled contract exceeds its fixed bound")
              hardware_profile = {
                  "format": "AOS_NIX_OFFLINE_HARDWARE_5",
                  "helper": original.pin(helper),
                  "loader": original.pin(helper_loader),
                  "compiled_contract_sha256": list(hashlib.sha256(contract).digest()),
                  "descriptor_limit": 4096,
                  "address_space_limit": 1073741824,
                  "child_descriptor_limit": 64,
                  "child_address_space_limit": 1073741824,
              }

          canonical_pin = original.pin(canonical)
          source_pin = original.pin(source_policy)
          provenance = dict(line.split("=", 1) for line in
                            (canonical.parent / "provenance").read_text().splitlines())
          if provenance.get("source_policy_sha256") != bytes(source_pin["sha256"]).hex():
              raise ValueError("canonical policy came from a different source")
          if provenance.get("readback_sha256") != bytes(canonical_pin["sha256"]).hex():
              raise ValueError("canonical readback differs from its actual producer")
          if matrix.stat().st_size == 0:
              raise ValueError("actual effective-policy comparison is empty")

          unit = unit_path.read_bytes()
          placeholder = b"OpenFile=@AOS_NIX_OFFLINE_PREPARE_PROFILE@:aos-nix-offline-prepare-profile:read-only\n"
          if len(unit) > 65536 or unit.splitlines(keepends=True).count(placeholder) != 1:
              raise ValueError("selected unit must contain exactly its closed profile role")
          if hardware_profile is not None:
              commands = [line for line in unit.splitlines(keepends=True)
                          if line.startswith(b"ExecStart=")]
              accepted = [f"ExecStart={executable} {command}\n".encode()
                          for command in ("initialize", "recover")]
              if len(commands) != 1 or commands[0] not in accepted:
                  raise ValueError("hardware unit must contain exactly its canonical command")
              neutral = b"".join(
                  b"ExecStart=@AOS_NIX_OFFLINE_HARDWARE_COMMAND@\n"
                  if line == commands[0] else line
                  for line in unit.splitlines(keepends=True))
              hardware_profile["unit_mode_neutral_sha256"] = list(
                  hashlib.sha256(neutral).digest())
          profile = {
              "format": "AOS_NIX_OFFLINE_PREPARE_STARTUP_3",
              "unit": "aos-sandbox-nix-floor-provision.service",
              "context": "system_u:system_r:aos_nix_offline_prepare_t",
              "executable": original.pin(executable),
              "pid1": original.pin(pid1),
              "loader": original.pin(loader),
              "runtime_files": files,
              "canonical_policy": canonical_pin,
              "source_policy": source_pin,
              "effective_matrix": original.pin(matrix),
              "unit_sha256": list(hashlib.sha256(unit).digest()),
          }
          if hardware_profile is not None:
              profile["hardware"] = hardware_profile
          encoded = json.dumps(profile, separators=(",", ":")).encode()
          if len(encoded) > 1048576:
              raise ValueError("offline startup comparison exceeds its fixed bound")
          output.write_bytes(encoded)
          PY
          chmod 0444 "$out/profile.json"
        '';
      }
    ];

    passthru.evidenceSources = [
      ./aos-normal-root-profile.py
      ./aos-selinux-runtime-manifest.py
      support
    ];
    meta = {
      description = if hardware
        then "Original offline Nix hardware startup comparisons; no independent approval authority"
        else "Prepare-only original offline Nix startup comparisons; no TPM or approval authority";
      license = "GPL-2.0-or-later";
    };
  }
