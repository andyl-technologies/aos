##! Checks real Source installation modules without inventing an installation policy.
##!
##! `incomplete` is a concrete negative fixture over the server image. The
##! positive entry takes authenticated installation modules containing actual
##! policy, credential names and Parent subdivisions. No option-presence stubs,
##! substitute startup-profile package, default vector or cap increase is used.
{pkgs, lib, mkSystem}: let
  parentMessage = "installed Source signer requires its genuine Parent and explicit Source receiving/sender F/M slices";
  profileMessage = "installed Source signer requires its exact image-delivered Root profile and all three PID1 pre-listen subject options";
  roleMessage = "protected Source origin v1 requires the immutable policy-labelled image and its exact single signer role, no auxiliary commands, PAM or EnvironmentFile; no helper user/PID/BPF/delegated namespaces or DynamicUser, and the exact source-built systemd loader profile; generic systemd modes keep their existing features";
  pinMessage = "Source signer and Root policy authority must load the same independently provisioned Source pin";
  rejects = message: system:
    builtins.any (check: check.message == message && !check.assertion)
      system.config.assertions;

  # This uses the actual registry, Source option type and enabled module body.
  # No policy or credential is guessed to make the installation pass.
  incomplete = mkSystem {
    systemName = "source-installation-incomplete";
    modules = [
      ../../systems/server.nix
      {aos.sandbox.sourceSignerService.enable = true;}
    ];
  };
  incompleteCache = mkSystem {
    systemName = "cache-installation-incomplete";
    modules = [
      ../../systems/server.nix
      {aos.sandbox.cacheSignerService.enable = true;}
    ];
  };
  incompleteCheck =
    assert incomplete.config.aos.sandbox.sourceSignerService.enable;
    assert incomplete.config.aos.sandbox.resourceBank.parentEnclosure == null;
    assert rejects parentMessage incomplete;
    assert rejects profileMessage incomplete;
    assert incompleteCache.config.aos.sandbox.cacheSignerService.enable;
    assert incompleteCache.config.aos.sandbox.resourceBank.parentEnclosure == null;
    assert rejects "installed Cache signer requires its genuine Parent and distinct explicit Cache receiving/sender F/M slices" incompleteCache;
    assert rejects "installed Cache signer requires its exact image-delivered Root profile and all PID1 pre-listen subject options" incompleteCache;
    pkgs.runCommand "aos-source-installation-incomplete-config" {} ''
      mkdir -p "$out"
      echo "PASS: real enabled Source and Cache reject missing Parent/profile" > "$out/result"
    '';

  forConfigurationModules = configurationModules: let
    evaluated = mkSystem {
      systemName = "source-installation-selected";
      modules = [../../systems/server.nix] ++ configurationModules;
    };
    pkgs = evaluated.pkgs;
    cfg = evaluated.config;
    sandbox = cfg.aos.sandbox;
    parent = sandbox.resourceBank.parentEnclosure;
    policy = sandbox.policyAuthority;
    source = sandbox.sourceSignerService;
    view = sandbox.sourceSignerView;
    service = cfg.systemd.services.aos-sandbox-source-signerd.serviceConfig;
    socket = cfg.systemd.sockets.aos-sandbox-source-signerd.socketConfig;
    expectedExec = "${source.package}/bin/aos-sandbox-source-signerd ${toString sandbox.controller.uid} ${toString sandbox.controller.gid} ${toString view.uid} ${toString view.gid}";
    flags = ["PassCredentials" "PassPIDFD" "PassSecurity" "PassSubjectBeforeListen"];
    sourceProfile = policy._normalStartupProfile;
    socketName = "aos-sandbox-source-signerd.socket";
    socketPrefix = "systemd/system/${socketName}.d/";
    socketLeaves = [socketName] ++ builtins.map (lib.removePrefix "systemd/system/")
      (builtins.filter (lib.hasPrefix socketPrefix)
        (builtins.attrNames cfg.system.build.systemdEtcEntries));
    cache = sandbox.cacheSignerService;
    cacheView = sandbox.cacheSignerView;
    expectedCacheExec = "${cache.package}/bin/aos-sandbox-cache-signerd ${toString sandbox.controller.uid} ${toString sandbox.controller.gid} ${toString cacheView.uid} ${toString cacheView.gid}";
    cacheSocketName = "aos-sandbox-cache-signerd.socket";
    cacheSocketPrefix = "systemd/system/${cacheSocketName}.d/";
    cacheSocketLeaves = [cacheSocketName] ++ builtins.map (lib.removePrefix "systemd/system/")
      (builtins.filter (lib.hasPrefix cacheSocketPrefix)
        (builtins.attrNames cfg.system.build.systemdEtcEntries));
    extend = module: evaluated.extendModules {modules = [module];};
    missingParent = extend ({lib, ...}: {
      aos.sandbox.resourceBank.parentEnclosure = lib.mkForce null;
    });
    wrongPin = extend ({lib, ...}: {
      aos.sandbox.sourceSignerService.credentials.publicKey = lib.mkForce "source-installation-wrong-pin";
    });
    extraCommand = extend ({lib, ...}: {
      systemd.services.aos-sandbox-source-signerd.serviceConfig.ExecStartPre =
        lib.mkForce "${pkgs.coreutils}/bin/true";
    });
    forbiddenDirectory = extend ({lib, ...}: {
      systemd.services.aos-sandbox-source-signerd.serviceConfig.StateDirectory =
        lib.mkForce "source-installation-forbidden-state";
    });
    wrongProfile = extend ({lib, ...}: {
      systemd.services.aos-sandbox-source-signerd.serviceConfig.OpenFile = lib.mkForce [];
    });
    validation =
      assert builtins.isList configurationModules && configurationModules != [];
      assert source.enable && view.enable && policy.enable && sandbox.controllerService.enable;
      assert cfg.aos.security.selinux.enable && cfg.aos.security.selinux.bootMode == "immutable-stage0";
      assert source.package == pkgs.aos-sandboxd && policy.package == pkgs.aos-sandboxd;
      assert import ../../modules/sandbox/_fixed-systemd-profile.nix {config = cfg; inherit pkgs;};
      assert parent != null && parent.sourceSignerReceiving != null && parent.sourceSignerSender != null;
      assert sandbox.resourceBank.policy != null && sandbox.resourceBank._parentImage != null;
      assert sourceProfile != null;
      assert service.OpenFile == ["${sourceProfile}/profile.json:aos-source-root-profile:read-only"];
      assert builtins.all (name: socket.${name} == true) flags;
      assert builtins.all (check: check.assertion) cfg.assertions;
      assert rejects parentMessage missingParent;
      assert rejects pinMessage wrongPin;
      assert rejects roleMessage extraCommand;
      assert rejects roleMessage forbiddenDirectory;
      assert rejects profileMessage wrongProfile;
      pkgs.runCommand "aos-source-selected-installation-contract" {
        nativeBuildInputs = [pkgs.python3 pkgs.coreutils];
        parentImage = sandbox.resourceBank._parentImage;
        bootstrapImage = sandbox.resourceBank._imagePolicy;
        unitImage = "${cfg.system.build.managerConfiguration}/systemd-units";
        rootProfile = sourceProfile;
        selectedPolicy = cfg.aos.security.selinux._productionPolicy;
        expectedSourceExec = expectedExec;
        cacheEnabled = if cache.enable then "yes" else "no";
        expectedCacheExec = if cache.enable then expectedCacheExec else "";
        cacheSocketLeavesJson = builtins.toJSON (lib.optionals cache.enable cacheSocketLeaves);
        dimensionJson = builtins.toJSON sandbox.resourceBank._dimensionOrder;
        contractJson = builtins.toJSON parent;
        socketLeavesJson = builtins.toJSON socketLeaves;
        profileValidator = ../../pkgs/system/_source-protected-profile.py;
      } ''
        ${pkgs.python3}/bin/python3 -B ${../../pkgs/system/tests/source-installation.py}
        mkdir -p "$out"
        cp "$parentImage/enclosure.bin" "$out/enclosure.bin"
        echo "PASS: actual Parent, Source unit/drop-ins, prelisten socket and selected packages" > "$out/result"
      '';
  in {
    inherit evaluated validation;
    parentImage = sandbox.resourceBank._parentImage;
    systemdUnits = "${cfg.system.build.managerConfiguration}/systemd-units";
    rootProfile = sourceProfile;
    selectedPolicy = cfg.aos.security.selinux._productionPolicy;
    canonicalReadback = cfg.aos.security.selinux._canonicalReadback;
    erofsLabels = import ../../tests/build/selinux-erofs-labels.nix {
      inherit lib pkgs;
      system = evaluated;
      policy = cfg.aos.security.selinux._productionPolicy;
    };
    # These are configuration-negative checks, not native failure receipts.
    negativeAssertions = {
      missingParent = rejects parentMessage missingParent;
      wrongPin = rejects pinMessage wrongPin;
      extraCommand = rejects roleMessage extraCommand;
      forbiddenDirectory = rejects roleMessage forbiddenDirectory;
      wrongProfile = rejects profileMessage wrongProfile;
    };
  };
in {
  inherit incomplete incompleteCheck forConfigurationModules;
  missingPositiveConfiguration = [
    "Explicit complete resourceBank.policy and parentEnclosure M/F/Source/Controller/optional Ownership and Cache subdivisions"
    "Actual enabled Controller, view, policy and supporting broker configuration with independently provisioned credential names"
    "Final selected Rust/systemd/policy package join and immutable-stage0 image configuration"
  ];
}
