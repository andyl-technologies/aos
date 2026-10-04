##! Closed online Nix startup comparisons, without provisioning authority.
{
  mkDerivation,
  buildPackages,
  aos-sandboxd,
  systemd,
  aos-selinux-production-policy,
  aos-selinux-kernel-policy-readback,
  aos-nix-runtime-tpm-helpers,
  role,
  identities,
  unitContract,
}: let
  controller = role == "controller";
  validRole = controller || role == "owner";
  executable = "${aos-sandboxd}/bin/" + (if controller then "aos-sandboxd" else "aos-sandbox-nixd");
  helper = "${aos-nix-runtime-tpm-helpers}/libexec/" + (if controller then "aos-nix-controller-tpm-helper" else "aos-nix-owner-tpm-helper");
  unit = if controller then "aos-sandboxd.service" else "aos-sandbox-nixd.service";
  context = if controller then "system_u:system_r:aos_sandbox_controller_t" else "system_u:system_r:aos_sandbox_nix_t";
  profileName = if controller then "aos-nix-controller-profile" else "aos-nix-owner-profile";
  profileBasename = if controller then "controller.json" else "owner.json";
  reader = aos-sandboxd.nixOnlineStoreReader;
  support = ./_aos-selinux-production-policy;
  sourcePolicy = "${aos-selinux-production-policy}/etc/selinux/aos/policy/policy.33";
  effectivePolicyChecker =
    if aos-selinux-production-policy ? effectivePolicyCheckerRelative
    then "${aos-selinux-production-policy}/${aos-selinux-production-policy.effectivePolicyCheckerRelative}"
    else "${support}/effective_policy.py";
in
  assert validRole;
  assert builtins.length identities == 4 && builtins.all (identity: identity > 0) identities;
  assert identities != [] && builtins.elem "nixOnlineStoreReader" (builtins.attrNames aos-sandboxd);
  mkDerivation {
    pname = "aos-nix-startup-profile";
    version = "2";
    src = ./aos-normal-root-profile.py;
    buildDeps = [buildPackages.python3 buildPackages.patchelf buildPackages.binutils buildPackages.setools];
    runtimeDeps = [];
    propagatedDeps = [];
    outputChecks = {};
    inherit unitContract role unit context profileName;
    identityJson = builtins.toJSON identities;
    passAsFile = ["unitContract"];
    exportReferencesGraph.nixOnlineRuntimeClosure = [aos-sandboxd aos-nix-runtime-tpm-helpers reader];
    nukeRefsKeep = [aos-sandboxd aos-nix-runtime-tpm-helpers reader systemd aos-selinux-production-policy aos-selinux-kernel-policy-readback];

    phases = [
      {
        name = "build";
        script = ''
          set -eu
          export PYTHONPATH=${buildPackages.setools}/lib/python3/site-packages
          ${buildPackages.python3}/bin/python3 -B ${effectivePolicyChecker} \
            ${sourcePolicy} > effective-policy.tsv
          test -s effective-policy.tsv
          mkdir -p "$out"
          install -m 0444 effective-policy.tsv "$out/effective-policy.tsv"
          install -m 0444 ${sourcePolicy} "$out/source-policy.33"

          # One existing ELF/closure engine; the new schema contains comparison
          # DATA only. The binary/reader are upstream of this profile in the DAG.
          ${buildPackages.python3}/bin/python3 -B - \
            "$src" ${./aos-selinux-runtime-manifest.py} "$NIX_ATTRS_JSON_FILE" \
            ${executable} ${helper} ${reader}/libexec/aos-nix-online-store-reader \
            ${systemd}/lib/systemd/systemd ${aos-selinux-kernel-policy-readback}/policy.33 \
            "$out/source-policy.33" "$out/effective-policy.tsv" "$unitContractPath" \
            ${buildPackages.patchelf}/bin/patchelf ${buildPackages.binutils}/bin/readelf \
            "$out/${profileBasename}" <<'PY'
          import hashlib
          import importlib.util
          import json
          import os
          import sys
          from pathlib import Path

          (source, helpers_path, attrs, executable, helper, reader, pid1,
           canonical, source_policy, matrix, contract, patchelf, readelf,
           output) = map(Path, sys.argv[1:])
          spec = importlib.util.spec_from_file_location("aos_original_image_primitives", source)
          if spec is None or spec.loader is None:
              raise ValueError("original image primitives cannot be imported")
          original = importlib.util.module_from_spec(spec)
          spec.loader.exec_module(original)
          helpers = original.load_runtime_helpers(helpers_path)
          paths = helpers.graph_paths(attrs, "nixOnlineRuntimeClosure")
          helpers.validate_symlinks(paths)
          closure = {str(path) for path in paths}

          members = {}
          loaders = []
          for program in (executable, helper, reader):
              if helpers.closure_owner(str(program), closure) is None:
                  raise ValueError("selected executable is outside its actual closure")
              loader, files = original.runtime_files(helpers, paths, program, patchelf, readelf)
              loaders.append(loader)
              for entry in files:
                  prior = members.get(entry["path"])
                  if prior is not None and prior != entry:
                      raise ValueError("selected runtime image pins disagree")
                  members[entry["path"]] = entry
          if not members or len(members) > 512:
              raise ValueError("selected runtime pin table exceeds its existing bound")

          canonical_pin = original.pin(canonical)
          source_pin = original.pin(source_policy)
          provenance = dict(line.split("=", 1) for line in
                            (canonical.parent / "provenance").read_text().splitlines())
          if provenance.get("source_policy_sha256") != bytes(source_pin["sha256"]).hex():
              raise ValueError("canonical policy came from another source")
          if provenance.get("readback_sha256") != bytes(canonical_pin["sha256"]).hex():
              raise ValueError("canonical policy readback differs from its producer")
          if matrix.stat().st_size == 0:
              raise ValueError("effective-policy comparison is empty")

          unit_bytes = contract.read_bytes()
          placeholder = ("OpenFile=@AOS_NIX_PROFILE@:" + os.environ["profileName"]
                         + ":read-only\n").encode()
          if len(unit_bytes) > 65536 or unit_bytes.splitlines(keepends=True).count(placeholder) != 1:
              raise ValueError("selected unit does not contain its sole profile role")
          profile = {
              "format": "AOS_NIX_STARTUP_2",
              "role": os.environ["role"],
              "unit": os.environ["unit"],
              "context": os.environ["context"],
              "identities": json.loads(os.environ["identityJson"]),
              "executable": original.pin(executable),
              "pid1": original.pin(pid1),
              "loader": original.pin(loaders[0]),
              "runtime_files": [members[path] for path in sorted(members)],
              "helper": original.pin(helper),
              "helper_loader": original.pin(loaders[1]),
              "canonical_policy": canonical_pin,
              "source_policy": source_pin,
              "effective_matrix": original.pin(matrix),
              "unit_sha256": list(hashlib.sha256(unit_bytes).digest()),
          }
          encoded = json.dumps(profile, separators=(",", ":")).encode()
          if len(encoded) > 1048576:
              raise ValueError("selected startup comparison exceeds its existing bound")
          output.write_bytes(encoded)
          PY
          chmod 0444 "$out/${profileBasename}"
        '';
      }
    ];

    passthru = {
      inherit role identities;
      evidenceSources = [./aos-normal-root-profile.py ./aos-selinux-runtime-manifest.py support];
    };
    meta = {
      description = "Original fixed online Nix startup comparisons, not floor authority";
      license = "GPL-2.0-or-later";
    };
  }
