##! Fixed-point checks for the package-owned attestation verifier service.
{
  lib,
  pkgs,
}: let
  evaluate = verifierConfig:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "attestation-verifier";
            stage = "host";
          };
          aos.services.attestationVerifier = verifierConfig;
        }
      ];
      packageModules = [
        (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
        {
          name = "aos";
          version = pkgs.aos.version;
          module = pkgs.aos.module + "/module.nix";
        }
      ];
    };
  disabled = evaluate {};
  disabledRequests = disabled.config.aos.abilities.requests;
  enabled = evaluate {
    enable = true;
    eventLog = "/var/lib/verifier/events.cel";
    quoteDir = "/var/lib/verifier/quote";
    nonceFile = "/var/lib/verifier/nonce";
    resultFile = "/var/lib/verifier/result.json";
    pcr15BaselineFile = "/etc/aos/pcr15-baseline";
    quoteIdentityFiles = ["/etc/aos/quote-identity.json"];
    catalogFiles = ["/etc/aos/catalog.json"];
  };
  abilities = enabled.config.aos.abilities;
  requests = abilities.requests;
  lifecycle = requests."aos:aos-attestation-verifier-lifecycle".parameters;
  command = builtins.head lifecycle.start;
  dependency = {
    _type = "aos-request-output-reference";
    request = "aos:local-filesystems";
    output = "resource";
  };
  portableOptionTree = options:
    builtins.all
    (name: let
      option = options.${name};
    in
      if option ? type
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrNames options);
in
  assert !(disabledRequests ? "aos:aos-attestation-verifier-lifecycle");
  assert disabled.config.aos.abilities.requirementTemplates == abilities.requirementTemplates;
  assert abilities.instances ? "aos:service";
  assert requests."aos:local-filesystems".parameters.scope == "local-filesystems";
  assert lifecycle.enabled == false;
  assert lifecycle.execution_model == "oneshot";
  assert lifecycle.configuration_change_action == "none";
  assert command
  == {
    executable = {
      artifact = lib.abilities.packageOutput {
        package = "aos";
        output = "apm";
      };
      entry_point = "bin/apm";
      arguments = [
        "--json"
        "attest"
        "verify"
        "--system"
        "--event-log"
        "/var/lib/verifier/events.cel"
        "--quote-dir"
        "/var/lib/verifier/quote"
        "--nonce-file"
        "/var/lib/verifier/nonce"
        "--result-file"
        "/var/lib/verifier/result.json"
        "--quote-identity-file"
        "/etc/aos/quote-identity.json"
        "--catalog-file"
        "/etc/aos/catalog.json"
        "--pcr15-baseline-file"
        "/etc/aos/pcr15-baseline"
      ];
    };
    ignore_failure = false;
  };
  assert requests."aos:aos-attestation-verifier-dependencies".parameters.after == [dependency];
  assert requests."aos:aos-attestation-verifier-dependencies".parameters.requires == [dependency];
  assert requests."aos:aos-attestation-verifier-directories".parameters.managed
  == [
    {
      path = "aos-attestation-verifier";
      purpose = "state";
      mode = "0750";
      retention = "persistent";
    }
  ];
  assert requests."aos:aos-attestation-verifier-identity".parameters.ephemeral;
  assert requests."aos:aos-attestation-verifier-isolation".parameters.network == "none";
  assert requests."aos:aos-attestation-verifier-hardening".parameters.isolation_domain_creation == "denied";
  assert portableOptionTree enabled.options.aos.services.attestationVerifier;
  assert !(enabled.config ? systemd); true
