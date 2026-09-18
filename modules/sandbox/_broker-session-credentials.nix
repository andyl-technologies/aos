##! modules/sandbox/_broker-session-credentials.nix — protected BSA custody wiring
{
  lib,
  pkgs,
}: let
  roleFiles = role:
    if role == "client"
    then [
      {
        option = "hello";
        installed = "client-hello-signing-key";
      }
      {
        option = "record";
        installed = "client-record-signing-key";
      }
    ]
    else if role == "broker"
    then [
      {
        option = "hello";
        installed = "broker-hello-signing-key";
      }
      {
        option = "record";
        installed = "broker-outcome-signing-key";
      }
    ]
    else throw "broker-session endpoint role must be client or broker";

  endpointFiles = endpoint:
    [
      {
        option = endpoint.options.manifest;
        credential = "${endpoint.name}-manifest";
        installed = "broker-session-manifest";
      }
    ]
    ++ map (file: {
      option = endpoint.options.${file.option};
      credential = "${endpoint.name}-${file.option}-key";
      inherit (file) installed;
    }) (roleFiles endpoint.role);

  endpointState = credentials: endpoint: let
    files = endpointFiles endpoint;
    selected = map (file: credentials.${file.option}) files;
    anyConfigured = lib.any (value: value != null) selected;
    completelyConfigured = lib.all (value: value != null) selected;
    custody = "${endpoint.journalRoot}/custody";
  in {
    assertions = [
      {
        assertion = !anyConfigured || completelyConfigured;
        message = "${endpoint.description} broker-session manifest and both role-local keys must be configured together";
      }
    ];

    loadCredentials =
      lib.optionals completelyConfigured (map (file: "${file.credential}:/run/credentials/@system/${credentials.${file.option}}")
        files);

    installCommands = lib.optionals completelyConfigured (
      [
        "${pkgs.coreutils}/bin/install -d -m 0700 ${endpoint.journalRoot}"
        "${pkgs.coreutils}/bin/install -d -m 0700 ${custody}"
      ]
      ++ map (file: "${pkgs.coreutils}/bin/install -m 0400 %d/${file.credential} ${custody}/${file.installed}")
      files
      ++ ["${pkgs.coreutils}/bin/chmod 0500 ${custody}"]
    );
  };
in {
  mkOptions = endpoints:
    lib.listToAttrs (lib.concatMap (endpoint:
      map (entry: {
        name = entry.name;
        value = lib.mkOption {
          type = lib.types.nullOr lib.serviceTypes.credentialName;
          default = null;
          description = "External system credential for the ${endpoint.description} broker-session ${entry.label}; its bytes never enter the Nix store.";
        };
      }) [
        {
          name = endpoint.options.manifest;
          label = "manifest";
        }
        {
          name = endpoint.options.hello;
          label = "hello signing key";
        }
        {
          name = endpoint.options.record;
          label =
            if endpoint.role == "client"
            then "record signing key"
            else "outcome signing key";
        }
      ])
    endpoints);

  configure = credentials: endpoints: let
    states = map (endpointState credentials) endpoints;
  in {
    assertions = lib.concatMap (state: state.assertions) states;
    loadCredentials = lib.concatMap (state: state.loadCredentials) states;
    installCommands = lib.concatMap (state: state.installCommands) states;
  };
}
