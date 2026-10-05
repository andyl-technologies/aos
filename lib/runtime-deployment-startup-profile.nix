##! Two fixed image comparisons over the existing ELF/runtime-closure engine.
{
  pkgs,
  publisher,
  helper,
  storage,
  systemd,
  policy,
  canonicalPolicy,
  publisherUnit,
  storageUnit,
  storageArguments,
}: let
  primitives = ../pkgs/security/aos-normal-root-profile.py;
  manifest = ../pkgs/security/aos-selinux-runtime-manifest.py;
  checkerRelative = policy.effectivePolicyCheckerRelative
    or (throw "Host runtime profiles require the delivered selected policy checker");
  checker =
    if checkerRelative == "share/aos/selected-policy-checker/effective_policy.py"
    then "${policy}/${checkerRelative}"
    else throw "Host runtime profiles require the fixed relative policy checker path";
  sourcePolicy = "${policy}/etc/selinux/aos/policy/policy.33";
  makeProfile = storageOnly: pkgs.mkDerivation {
    pname = if storageOnly then "aos-runtime-deployment-storage-profile" else "aos-runtime-deployment-startup-profile";
    version = if storageOnly then "2" else "1";
    src = primitives;
    buildDeps = [pkgs.buildPackages.python3 pkgs.buildPackages.patchelf pkgs.buildPackages.binutils pkgs.buildPackages.setools];
    runtimeDeps = [];
    propagatedDeps = [];
    outputChecks = {};
    selectedStorage = if storageOnly then "1" else "0";
    unitContract = if storageOnly then storageUnit else publisherUnit;
    argumentsJson = builtins.toJSON storageArguments;
    passAsFile = ["unitContract"];
    exportReferencesGraph.runtimeDeploymentClosure = if storageOnly then [storage] else [publisher helper];
    nukeRefsKeep = [publisher helper storage systemd policy canonicalPolicy];

    phases = [{
      name = "build";
      script = ''
        set -eu
        mkdir -p "$out"
        install -m 0444 ${sourcePolicy} "$out/source-policy.33"
        export PYTHONPATH=${pkgs.buildPackages.setools}/lib/python3/site-packages
        ${pkgs.buildPackages.python3}/bin/python3 -B ${checker} \
          ${sourcePolicy} > effective-policy.tsv
        test -s effective-policy.tsv
        install -m 0444 effective-policy.tsv "$out/effective-policy.tsv"

        # The existing helper supplies all graph, ELF, loader and hash rules.
        # This selected wrapper adds only fixed schema fields and unit bytes.
        ${pkgs.buildPackages.python3}/bin/python3 -B - \
          "$src" ${manifest} "$NIX_ATTRS_JSON_FILE" \
          ${publisher}/bin/aos-sandbox-runtime-publisher \
          ${helper}/libexec/aos-runtime-deployment-tpm-helper \
          ${storage}/bin/aos-storaged ${systemd}/lib/systemd/systemd \
          ${canonicalPolicy}/policy.33 "$out/source-policy.33" \
          "$out/effective-policy.tsv" "$unitContractPath" \
          ${pkgs.buildPackages.patchelf}/bin/patchelf \
          ${pkgs.buildPackages.binutils}/bin/readelf "$out" <<'PY'
        import hashlib
        import importlib.util
        import json
        import os
        import sys
        from pathlib import Path

        (source, helper_source, attrs, publisher, helper, storage, pid1,
         canonical, source_policy, matrix, contract, patchelf, readelf,
         output) = map(Path, sys.argv[1:])
        spec = importlib.util.spec_from_file_location("aos_original_image_primitives", source)
        if spec is None or spec.loader is None:
            raise ValueError("original image primitives unavailable")
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        helpers = original.load_runtime_helpers(helper_source)
        paths = helpers.graph_paths(attrs, "runtimeDeploymentClosure")
        helpers.validate_symlinks(paths)
        closure = {str(path) for path in paths}
        storage_only = os.environ["selectedStorage"] == "1"
        programs = (storage,) if storage_only else (publisher, helper)
        members = {}
        loaders = []
        for program in programs:
            if helpers.closure_owner(str(program), closure) is None:
                raise ValueError("selected executable is outside its actual closure")
            loader, files = original.runtime_files(helpers, paths, program, patchelf, readelf)
            loaders.append(loader)
            for entry in files:
                prior = members.get(entry["path"])
                if prior is not None and prior != entry:
                    raise ValueError("selected runtime image pins disagree")
                members[entry["path"]] = entry
        if not members or len(members) > 512 or not closure or len(closure) > 512:
            raise ValueError("selected runtime inventory exceeds its fixed bounds")

        canonical_pin = original.pin(canonical)
        source_pin = original.pin(source_policy)
        provenance = dict(line.split("=", 1) for line in
                          (canonical.parent / "provenance").read_text().splitlines())
        if provenance.get("source_policy_sha256") != bytes(source_pin["sha256"]).hex():
            raise ValueError("canonical policy has a different source")
        if provenance.get("readback_sha256") != bytes(canonical_pin["sha256"]).hex():
            raise ValueError("canonical policy readback differs from its producer")
        unit_bytes = contract.read_bytes()
        if not unit_bytes or len(unit_bytes) > 65536:
            raise ValueError("selected fixed unit exceeds its bound")

        profile = {
            "format": "AOS_RUNTIME_DEPLOYMENT_STORAGE_2" if storage_only else "AOS_RUNTIME_DEPLOYMENT_STARTUP_1",
            "unit": "aos-storaged.service" if storage_only else "aos-sandbox-runtime-publisher.service",
            "executable": original.pin(programs[0]),
            "loader": original.pin(loaders[0]),
            "runtime_files": [members[path] for path in sorted(members)],
            "closure_roots": sorted(closure),
            "canonical_policy": canonical_pin,
            "unit_sha256": list(hashlib.sha256(unit_bytes).digest()),
        }
        if storage_only:
            profile["context"] = "system_u:system_r:aos_sandbox_storage_t"
            profile["arguments"] = json.loads(os.environ["argumentsJson"])
            basename = "storage.json"
        else:
            placeholder = b"OpenFile=@AOS_RUNTIME_DEPLOYMENT_PROFILE@:aos-runtime-deployment-startup-profile:read-only\n"
            if unit_bytes.splitlines(keepends=True).count(placeholder) != 1:
                raise ValueError("publisher profile self-reference is not unique")
            profile.update({
                "owner_context": "system_u:system_r:aos_runtime_deployment_publisher_t",
                "helper_context": "system_u:system_r:aos_runtime_deployment_helper_t",
                "pid1": original.pin(pid1),
                "source_policy": source_pin,
                "effective_matrix": original.pin(matrix),
            })
            profile = {
                "format": "AOS_RUNTIME_DEPLOYMENT_CANARY_STARTUP_2",
                "publisher": profile,
                "canary_storage": original.pin(Path(os.environ["storageProfile"]) / "storage.json"),
            }
            basename = "profile.json"
        encoded = json.dumps(profile, separators=(",", ":")).encode()
        if len(encoded) > 1048576:
            raise ValueError("selected profile exceeds its original bound")
        (output / basename).write_bytes(encoded)
        PY
        chmod 0444 "$out/"*.json
      '';
    }];
  };
  storageProfile = makeProfile true;
in {
  storage = storageProfile;
  publisher = (makeProfile false).overrideAttrs (_: {inherit storageProfile;});
}
