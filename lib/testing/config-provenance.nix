##! Resolver-authenticated package and operator custody in bounded native evaluation.
{pkgs, ...}: let
  lib = import ../default.nix {system = pkgs.bash.system;};
  payload = import ../../tests/effects/_fixture-payload.nix;
  fixtureRoot = ../../tests/fixtures/config-provenance;
  package = name: dependencies: {
    type = "derivation";
    pname = name;
    version = "1";
    system = pkgs.bash.system;
    outPath = payload name;
    module = builtins.path {
      path = fixtureRoot + "/${name}";
      name = "${name}-provenance-module";
    };
    moduleDeps = dependencies;
    meta.mainProgram = "provenance-fixture";
  };
  demo = package "provenance-demo" [];
  group = package "group-provider" [demo];
  evaluate = packages: operatorModules: lib.evalPackageModules {
    scope = ["profile" "provenance"];
    inherit packages operatorModules;
    modules = [
      ({lib, provenance, ...}: {
        _module.strict = true;
        options.provenanceOwner = lib.mkOption {
          type = lib.types.str;
          readOnly = true;
        };
        config.provenanceOwner = provenance.ownerOfOption ["aos" "provenance" "message"];
      })
    ];
  };
  base = evaluate [demo] [];
  operator = evaluate [demo] [{
    _file = "provenance-demo/module.nix";
    aos.provenance.message = "operator-owned";
    aos.abilities.provenance.operations.write.effects.host.input = {
      path = "/etc/operator.conf";
      text = "operator";
    };
  }];
  imported = evaluate [demo] [{imports = [(fixtureRoot + /operator.nix)];}];
  connected = evaluate [group] [({config, ...}: {
    aos.abilities.provenance.operations.write.effects.host.input = {
      path = "/etc/operator-group.conf";
      text = config.aos.abilities.provenance.operations.write.effects.group.outputs.path;
    };
  })];
  rejects = evaluated: !(builtins.tryEval (builtins.deepSeq evaluated.deployment true)).success;
  byInstance = evaluated: name:
    builtins.head (builtins.filter
      (node: lib.last node.identity == name)
      (builtins.attrValues evaluated.deployment.graph.nodes));
  baseNode = byInstance base "demo";
  hostNode = byInstance operator "host";
  groupNode = byInstance connected "group";
  connectedNode = byInstance connected "host";
  forgedProvenance = evaluate [demo] [{
    _provenance = "package:provenance-demo";
    aos.provenance.message = "forged";
  }];
  mixedEffectOwners = evaluate [demo (package "group-provider" [demo])] [{ }];
  collisionPackage = group // {
    module = builtins.path {
      path = fixtureRoot + /effect-collision;
      name = "provenance-effect-collision";
    };
  };
  # A shared dependency is legitimate; sharing ownership of one effect is not.
  collision = evaluate [demo collisionPackage] [];
  checks = {
    packageOwner = baseNode.owner == "provenance-demo"
      && baseNode.identity == ["profile" "provenance" "provenance-demo" "provenance" "write" "demo"]
      && baseNode.input.text == "package-owned"
      && base.config.provenanceOwner == "provenance-demo";
    nativeArtifact = baseNode.handler.executable == "${demo}/bin/provenance-fixture"
      && builtins.length base.deployment.packages == 1
      && (builtins.head base.deployment.packages).artifacts.package.name == "provenance-demo";
    operatorCustody = operator.config.provenanceOwner == "@host"
      && (byInstance operator "demo").owner == "provenance-demo"
      && (byInstance operator "demo").input.text == "operator-owned"
      && hostNode.owner == "@environment";
    importedOperatorCustody = imported.config.provenanceOwner == "@host"
      && (byInstance imported "demo").input.text == "imported-operator";
    explicitMixedOwnerDependency = groupNode.owner == "group-provider"
      && connectedNode.owner == "@environment"
      && connectedNode.dependencies == [(builtins.hashString "sha256" (builtins.toJSON groupNode.identity))]
      && !rejects mixedEffectOwners;
    packageImportBoundary = rejects (evaluate [demo (package "path-contributor" [demo])] []);
    portableNamespaceBoundary = rejects (evaluate [demo (package "session-contributor" [demo])] []);
    resolverProvenanceCannotBeForged = rejects forgedProvenance;
    effectCollisionRejected = rejects collision;
  };
  loginPolicy = operatorModules: lib.evalPackageModules {
    scope = ["profile" "login-provenance"];
    packages = [pkgs.aos-host-policy pkgs.systemd];
    inherit operatorModules;
  };
  loginBase = loginPolicy [];
  loginSession = loginPolicy [{
    environment.sessionVariables.PROVENANCE_TEST = "host";
    aos.abilities.configuration.operations.file.effects.operator-login.input = {
      path = "/etc/profile.d/operator-login.sh";
      content = "export PROVENANCE_TEST=host\n";
      mode = "0644";
    };
  }];
  # Derived login files keep their authenticated package owner when operator
  # session values change; separately authored files retain operator custody.
  loginPathChecks = {
    retainedLoginPathCustody =
      (byInstance loginBase "login-package-path").owner == "aos-host-policy"
      && (byInstance loginBase "login-package-path").input.path == "/etc/profile.d/10-apm-path.sh"
      && (byInstance loginSession "login-package-path").owner == "aos-host-policy";
    authoredLoginPathCustody =
      (byInstance loginSession "operator-login").owner == "@environment"
      && (byInstance loginSession "operator-login").input.path == "/etc/profile.d/operator-login.sh";
  };
  mkCheck = name: valid:
    assert valid;
      pkgs.mkDerivation {
        pname = "config-provenance-${name}-check";
        version = "0";
        src = null;
        phases = [{
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }];
      };
  suites = lib.mapAttrs mkCheck (checks // loginPathChecks);
in {
  inherit suites;
  checks = checks // loginPathChecks;
  all = pkgs.mkDerivation {
    pname = "config-provenance-check";
    version = "0";
    src = null;
    buildDeps = builtins.attrValues suites;
    phases = [{
      name = "check";
      script = ''
        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }];
  };
}
