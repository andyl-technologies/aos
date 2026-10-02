##! Package-owned OpenLDAP server settings and native runtime configuration.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.openldap;
  serviceEnabled = config.aos.services."openldap.main".enable;
  inherit (lib) mkOption;
  types = lib.types;
  operations = config.aos.abilities;
  positiveInt = types.ints.between 1 9007199254740991;
  ldapUrl = types.strMatching "(ldap|ldaps|ldapi)://[^[:space:]]*";
  ldapUrls = types.listOf ldapUrl;
  distinguishedName = types.strMatching "[A-Za-z][^[:cntrl:]]*";
  credentialReference = types.submodule operations.credential.operations.deliver.input;
  credentialConfigured = value: (value.name != null) != (value.resource != null);
  credentialPath = name: operations.credential.operations.deliver.effects."openldap-${name}".outputs.path;
  literal = text: text;
  executionPath = value: value;
  artifactPath = path: "${package}/${path}";
  artifactDirectoryPath = artifactPath;
  quoted = value: lib.replaceStrings ["\\" "\""] ["\\\\" "\\\""] value;
  credentialContent = name: {
    credentialPath = credentialPath name;
    maximumBytes = 65536;
  };
  command = entryPoint: arguments: {
    executable = {
      path = "${package}/${entryPoint}";
      inherit arguments;
    };
    ignore_failure = false;
  };
  credentialsFor = withTls:
    [
      {
        name = "root-password";
        reference = cfg.rootPassword;
      }
    ]
    ++ lib.optionals withTls [
      {
        name = "tls-certificate";
        reference = cfg.tls.certificate;
      }
      {
        name = "tls-private-key";
        reference = cfg.tls.privateKey;
      }
      {
        name = "tls-ca";
        reference = cfg.tls.trustedCa;
      }
    ];
  configurationFragmentsFor = withTls:
    [
      (literal "include ")
      (artifactPath "etc/openldap/schema/core.schema")
      (literal "\ninclude ")
      (artifactPath "etc/openldap/schema/cosine.schema")
      (literal "\ninclude ")
      (artifactPath "etc/openldap/schema/inetorgperson.schema")
      (literal "\nmodulepath ")
      (artifactDirectoryPath "libexec/openldap")
      (literal "\npidfile ")
      (executionPath (operations.filesystem.operations.directory.effects.openldap-runtime.outputs.path))
      (literal "/slapd.pid\nargsfile ")
      (executionPath (operations.filesystem.operations.directory.effects.openldap-runtime.outputs.path))
      (literal "/slapd.args\ndatabase mdb\nmaxsize ${toString cfg.database.maxBytes}\nsuffix \"${quoted cfg.suffix}\"\nrootdn \"${quoted cfg.rootDn}\"\ndirectory ")
      (executionPath (operations.filesystem.operations.directory.effects.openldap-data.outputs.path))
      (literal "\nindex objectClass eq\n")
    ]
    ++ lib.optionals withTls [
      (literal "TLSCertificateFile ")
      (executionPath (credentialPath "tls-certificate"))
      (literal "\nTLSCertificateKeyFile ")
      (executionPath (credentialPath "tls-private-key"))
      (literal "\nTLSCACertificateFile ")
      (executionPath (credentialPath "tls-ca"))
      (literal "\nTLSVerifyClient ${cfg.tls.verifyClient}\n")
    ]
    ++ [
      (literal "rootpw {CLEARTEXT}")
      (credentialContent "root-password")
      (literal "\n")
    ];
  usedCredentials = credentialsFor cfg.tls.enable;
  account = operations.identity.operations.principal.effects.openldap.outputs.name;
  group = operations.identity.operations.group.effects.openldap.outputs.name;
  service = {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = [];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "shared";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = true;
      writable_executable_memory = false;
      isolation_domains = [];
      network_families = ["ipv4" "ipv6" "local"];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "all";
      security_label = "aos-pkg-openldap";
      operation_architectures = [];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "return-permission-denied";
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    service = "openldap";
    lifecycle = {
      description = "OpenLDAP directory server";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [
        (command "sbin/slaptest" [
          "-u"
          "-f"
          (operations.configuration.operations.file.effects.openldap.outputs.path)
        ])
      ];
      start = [
        (command "libexec/slapd" [
          "-d"
          "0"
          "-f"
          (operations.configuration.operations.file.effects.openldap.outputs.path)
          "-h"
          (lib.concatStringsSep " " cfg.listenUrls)
        ])
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 0;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [(operations.network.operations.ready.effects.openldap.outputs.resource)];
      before = [];
      requires = [];
      wants = [(operations.network.operations.ready.effects.openldap.outputs.resource)];
    };
    credentials =
      if cfg.tls.enable
      then {
        views = builtins.map (credential: {
          inherit (credential) name;
          inherit (credential.reference) encrypted;
          reference = credentialPath credential.name;
          optional = false;
        }) (builtins.filter (credential: credential.name != "root-password") usedCredentials);
      }
      else null;
    configuration.views = [
      {
        name = "server";
        source = operations.configuration.operations.file.effects.openldap.outputs.path;
        optional = false;
      }
    ];
    storage.mounts = [
      {
        name = "data";
        source = operations.filesystem.operations.directory.effects.openldap-data.outputs.path;
        access = "read-write";
      }
      {
        name = "runtime";
        source = operations.filesystem.operations.directory.effects.openldap-runtime.outputs.path;
        access = "read-write";
      }
    ];
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = [];
      directory_mode = "0750";
    };
    identity = {
      principal = operations.identity.operations.principal.effects.openldap.outputs.name;
      primary_group = operations.identity.operations.group.effects.openldap.outputs.name;
      supplementary_groups = [];
      ephemeral = false;
      file_creation_mask = "0077";
    };
    isolation = {
      privilege = "unprivileged";
      filesystem = "read-only-system";
      network = "host";
      process_visibility = "host";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
in {
  options.aos.openldap = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned OpenLDAP server.";
    };
    listenUrls = mkOption {
      type = ldapUrls;
      default = ["ldap://127.0.0.1:389/"];
      description = "LDAP, LDAPS, or local-domain listener URLs passed to slapd.";
    };
    suffix = mkOption {
      type = distinguishedName;
      default = "dc=example,dc=org";
      description = "Distinguished-name suffix served by the primary directory database.";
    };
    rootDn = mkOption {
      type = distinguishedName;
      default = "cn=admin,dc=example,dc=org";
      description = "Directory administrator distinguished name for the primary database.";
    };
    rootPassword = mkOption {
      type = credentialReference;
      default = {};
      description = "Typed credential containing the directory administrator password.";
    };
    database.maxBytes = mkOption {
      type = positiveInt;
      default = 1073741824;
      description = "Maximum LMDB database size in bytes.";
    };
    tls = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable TLS configuration and permit LDAPS listeners.";
      };
      certificate = mkOption {
        type = credentialReference;
        default = {};
        description = "Typed credential containing the LDAP server certificate.";
      };
      privateKey = mkOption {
        type = credentialReference;
        default = {};
        description = "Typed credential containing the LDAP server private key.";
      };
      trustedCa = mkOption {
        type = credentialReference;
        default = {};
        description = "Typed credential containing the trusted certificate authority bundle.";
      };
      verifyClient = mkOption {
        type = types.enum ["allow" "demand" "never" "try"];
        default = "demand";
        description = "Client-certificate verification policy applied to TLS sessions.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.listenUrls != [];
          message = "OpenLDAP requires at least one listener URL";
        }

        {
          assertion =
            !serviceEnabled
            || credentialConfigured cfg.rootPassword;
          message = "openldap.enable requires an openldap.rootPassword credential reference";
        }
        {
          assertion =
            !cfg.tls.enable
            || builtins.all credentialConfigured [
              cfg.tls.certificate
              cfg.tls.privateKey
              cfg.tls.trustedCa
            ];
          message = "OpenLDAP TLS requires certificate, private-key, and trusted-CA credential references";
        }
        {
          assertion =
            cfg.tls.enable
            || builtins.all (url: !(lib.hasPrefix "ldaps://" url)) cfg.listenUrls;
          message = "ldaps listen URLs require openldap.tls.enable";
        }
      ];
      aos.services."openldap.main" = lib.mkDefault (service // {enable = lib.mkDefault cfg.enable;});
    }
    (lib.mkIf serviceEnabled {
      aos.abilities = {
        identity.operations = {
          group.effects.openldap.input.name = "openldap";
          principal.effects.openldap.input = {
            name = "openldap";
            description = "OpenLDAP directory service";
            home_directory = "/var/lib/aos-pkg-openldap";
            primary_group = operations.identity.operations.group.effects.openldap.outputs.name;
          };
        };
        filesystem.operations.directory.effects = {
          openldap-state = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-pkg-openldap";
              mode = "0700";
              owner = account;
              group = group;
            };
          };
          openldap-data = {
            lifetime = "persistent";
            input = {
              path = "/var/lib/aos-pkg-openldap/data";
              parentResource = operations.filesystem.operations.directory.effects.openldap-state.outputs.resource;
              mode = "0700";
              owner = account;
              group = group;
            };
          };
          openldap-runtime.input = {
            path = "/run/aos-pkg-openldap";
            mode = "0700";
            owner = account;
            group = group;
          };
        };
        network.operations.ready.effects.openldap.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        credential.operations.deliver.effects = builtins.listToAttrs (builtins.map (credential: {
            name = "openldap-${credential.name}";
            value.input = credential.reference;
          })
          usedCredentials);
        configuration.operations.file.effects.openldap.input = {
          path = "/etc/aos/packages/openldap/slapd.conf";
          fragments = configurationFragmentsFor cfg.tls.enable;
          mode = "0600";
          owner = account;
          group = group;
        };
      };
    })
  ];
}
