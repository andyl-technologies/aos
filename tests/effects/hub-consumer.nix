##! Checks native Hub service policy and typed identity/storage/credential ordering.
let
  lib = import ../../lib {system = "x86_64-linux";};
  artifactLib = import ../../lib/packages/artifacts.nix {};
  fixturePayload = import ./_fixture-payload.nix;
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (fixturePayload name);
    outputs.out = toString (fixturePayload name);
    mainProgram = name;
  };
  record = name: source: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package = artifact name;
      dependencies = {};
    };
  };
  evaluate = hubConfiguration:
    lib.evalPackageModules {
      scope = ["test" "native-hub"];
      packageModules = [
        (record "service-management" ../../pkgs/system/_service-management)
        (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider)
        (record "aos-hub" ../../pkgs/tools/aos-hub/_aos-hub)
      ];
      operatorModules = [
        {
          aos.registry-hub = hubConfiguration;
          aos.abilities = builtins.listToAttrs (builtins.map (ability: {
              name = ability.name;
              value.operations = builtins.listToAttrs (builtins.map (operation: {
                  name = operation;
                  value.handler.program = artifactLib.value (artifact "${ability.name}-handler");
                })
                ability.operations);
            }) [
              {
                name = "serviceManagement";
                operations = ["realize"];
              }
              {
                name = "identity";
                operations = ["group" "principal"];
              }
              {
                name = "network";
                operations = ["ready"];
              }
              {
                name = "credential";
                operations = ["deliver"];
              }
            ]);
        }
      ];
    };
  evaluated = evaluate {
    enable = true;
    listen = "127.0.0.1:18420";
    externalUrl = "https://hub.example.test";
    reindexInterval = 15;
    deploymentId = "hub-production-v1";
    releaseReceiptKeyId = "hub-publication-v1";
    channelReceiptKeyId = "hub-channel-v1";
    credentials = {
      jwtSecret = "hub-jwt";
      routeReservationKeys = "hub-route-keys";
      domainProbeSignerManifest = "hub-probe-manifest";
      cloudflareApiToken = "hub-cloudflare-token";
      releaseReceiptKey = "hub-release-receipt-key";
      channelReceiptKey = "hub-channel-receipt-key";
      releasePublicationKeys = "hub-publication-keys";
      qualificationKeys = "hub-qualification-keys";
    };
  };
  invalid = evaluate {enable = true;};
  incompleteRelease = evaluate {
    enable = true;
    deploymentId = "incomplete-release-authority";
    credentials = {
      routeReservationKeys = "hub-route-keys";
      domainProbeSignerManifest = "hub-probe-manifest";
    };
  };
  nodes = builtins.attrValues evaluated.config.aos.activation.graph.nodes;
  service = builtins.head (builtins.filter (node: node.input ? service && node.input.service == "aos-hub") nodes);
  allocations = builtins.filter (node: node.input ? path && node.input.path == "/var/lib/aos-hub") nodes;
  credentials = builtins.filter (node: builtins.elemAt node.identity 3 == "credential" && builtins.elemAt node.identity 4 == "deliver") nodes;
  credentialViews = builtins.listToAttrs (builtins.map (view: {
      name = view.name;
      value = view;
    })
    service.input.credentials.views);
  expectedCredentialEnvironment = {
    cloudflare-api-token = "HUB_CLOUDFLARE_API_TOKEN_FILE";
    release-receipt-key = "HUB_RELEASE_RECEIPT_KEY_FILE";
    channel-receipt-key = "HUB_CHANNEL_RECEIPT_KEY_FILE";
    release-publication-keys = "HUB_RELEASE_PUBLICATION_KEYS_FILE";
    qualification-keys = "HUB_QUALIFICATION_KEYS_FILE";
  };
  expectedCredentialInstances = {
    jwt-secret = "jwtSecret";
    domain-probe-signers = "domainProbeSignerManifest";
    route-reservation-keys = "routeReservationKeys";
  };
  command = builtins.head service.input.lifecycle.start;
  assertionsPass = evaluated: builtins.all (entry: entry.assertion) evaluated.config.assertions;
  checks = {
    hubPreservesStateAccountIds = evaluated.config.aos.abilities.identity.operations.group.effects.hub.input.requested_id == 802 && evaluated.config.aos.abilities.identity.operations.principal.effects.hub.input.requested_id == 802;
    hubStableManagerIdentity = service.input.service == "aos-hub" && service.input.instance == "hub";
    hubUsesNativeService = evaluated.config.aos.services.hub.enable && service.owner == "service-management";
    hubRetainsPersistentStorage = builtins.length allocations == 1 && (builtins.head allocations).lifetime == "persistent";
    hubUsesExactPayload = (builtins.head service.input.lifecycle.start).executable.path == "${fixturePayload "aos-hub"}/bin/aos-hub";
    hubKeepsPrivateIdentity = service.input.isolation.privilege == "unprivileged" && service.input.identity.principal._type == "aos-effect-output";
    hubHasTypedCredentials = builtins.length credentials == 8 && builtins.length service.input.credentials.views == 8;
    hubKeepsConfiguredArguments = builtins.elem "127.0.0.1:18420" command.executable.arguments && builtins.elem "15" command.executable.arguments;
    hubCredentialsKeepTypedPaths = builtins.all (view: view.reference._type == "aos-effect-output" && view.reference.output == "path") service.input.credentials.views;
    hubCredentialsKeepOwners = builtins.all (name:
      credentialViews.${name}.reference.identity == ["test" "native-hub" "aos-hub" "credential" "deliver" "hub-${expectedCredentialInstances.${name}}"])
    (builtins.attrNames expectedCredentialInstances);
    hubCredentialsKeepEnvironment = builtins.all (name:
      credentialViews.${name}.environment_variable == expectedCredentialEnvironment.${name})
    (builtins.attrNames expectedCredentialEnvironment);
    hubRejectsMissingAuthority = !(assertionsPass invalid);
    hubRejectsPartialReleaseAuthority = !(assertionsPass incompleteRelease);
    hubOrdersPrerequisites = builtins.length service.dependencies >= 4;
  };
in
  assert builtins.all (value: value) (builtins.attrValues checks); checks
