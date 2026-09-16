##! Typed package-owned OpenLDAP server abilities.
{
  config,
  lib,
  ...
}: let
  cfg = config.openldap;
  inherit (lib) mkOption;
  inherit (lib.abilities) resultOf;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  abilityTypes = lib.abilities.types;

  positiveInt = abilityTypes.integer {
    minimum = 1;
    maximum = abilityTypes.limits.maxSafeInteger;
  };
  ldapUrl = abilityTypes.refined {
    name = "OpenLDAP listener URL";
    description = "an LDAP, LDAPS, or local-domain listener URL";
    type = abilityTypes.runtimeString;
    constraints = [{kind = "string-pattern"; pattern = "(ldap|ldaps|ldapi)://[^[:space:]]*";}];
  };
  ldapUrls = abilityTypes.refined {
    name = "OpenLDAP listener URLs";
    description = "a non-empty list of OpenLDAP listener URLs";
    type = abilityTypes.list {
      element = ldapUrl;
      maxItems = abilityTypes.limits.maxCollectionItems;
    };
    constraints = [{kind = "minimum-size"; minimum = 1;}];
  };
  distinguishedName = abilityTypes.refined {
    name = "OpenLDAP distinguished name";
    description = "a non-empty distinguished name without control characters";
    type = abilityTypes.runtimeString;
    constraints = [{kind = "string-pattern"; pattern = "[A-Za-z][^[:cntrl:]]*";}];
  };
  credentialReference = serviceTypes.credentialReference;
  literal = text: {
    kind = "literal";
    inherit text;
  };
  executionPath = value: {
    kind = "execution-path";
    inherit value;
  };
  artifactPath = path: {
    kind = "artifact-file-path";
    reference = {
      artifact = lib.abilities.packageOutput {};
      inherit path;
    };
  };
  artifactDirectoryPath = path: {
    kind = "artifact-directory-path";
    reference = {
      artifact = lib.abilities.packageOutput {};
      inherit path;
    };
  };
  quoted = value: lib.replaceStrings ["\\" "\""] ["\\\\" "\\\""] value;
  credentialContent = name: {
    kind = "credential-content";
    resource = resultOf "credential-${name}" "retained-resource";
    path = resultOf "credential-${name}" "credential-path";
  };
  producer = key: interface: parameters:
    serviceManagement.forProducer {
      consumerInstance = "openldap";
      inherit key interface parameters;
    };
  command = entryPoint: arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = entryPoint;
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
      (executionPath (resultOf "runtime-storage" "storage-path"))
      (literal "/slapd.pid\nargsfile ")
      (executionPath (resultOf "runtime-storage" "storage-path"))
      (literal "/slapd.args\ndatabase mdb\nmaxsize ${toString cfg.database.maxBytes}\nsuffix \"${quoted cfg.suffix}\"\nrootdn \"${quoted cfg.rootDn}\"\ndirectory ")
      (executionPath (resultOf "data-view" "storage-path"))
      (literal "\nindex objectClass eq\n")
    ]
    ++ lib.optionals withTls [
      (literal "TLSCertificateFile ")
      (executionPath (resultOf "credential-tls-certificate" "credential-path"))
      (literal "\nTLSCertificateKeyFile ")
      (executionPath (resultOf "credential-tls-private-key" "credential-path"))
      (literal "\nTLSCACertificateFile ")
      (executionPath (resultOf "credential-tls-ca" "credential-path"))
      (literal "\nTLSVerifyClient ${cfg.tls.verifyClient}\n")
    ]
    ++ [
      (literal "rootpw {CLEARTEXT}")
      (credentialContent "root-password")
      (literal "\n")
    ];
  abilityFragmentsFor = withTls: let
    credentials = credentialsFor withTls;
    persistentStorage = producer "state-storage" serviceManagement.interfaces.persistentStorageAllocation {
      name = "state";
      purpose = "state";
      mode = "0700";
    };
    runtimeStorage = producer "runtime-storage" serviceManagement.interfaces.storageAllocation {
      name = "runtime";
      purpose = "runtime";
      mode = "0700";
    };
    dataView = producer "data-view" serviceManagement.interfaces.storageView {
      name = "data";
      source = resultOf "state-storage" "retained-resource";
      source_path = resultOf "state-storage" "planned-path";
      access = "read-write";
      relative_path = "data";
    };
    group = producer "service-group" serviceManagement.interfaces.groupResolution {
      name = "openldap";
      allocation = "managed";
    };
    principal = producer "service-principal" serviceManagement.interfaces.principalResolution {
      name = "openldap";
      allocation = "managed";
      description = "OpenLDAP directory service";
      home_directory = resultOf "state-storage" "storage-path";
      login_access = "disabled";
      primary_group = resultOf "service-group" "group-name";
      supplementary_groups = [];
    };
    networkReadiness = producer "network-readiness" serviceManagement.interfaces.networkReadiness {
      scope = "configured-connectivity";
      address_families = ["ipv4" "ipv6"];
    };
    credentialRequests = serviceManagement.forCredentialReferences {
      consumerInstance = "openldap";
      references =
        builtins.map (credential: {
          key = "credential-${credential.name}";
          inherit (credential) name reference;
        })
        credentials;
    };
    configurationRequest = serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "openldap";
      declaration = {
        name = "server-configuration";
        source = {
          kind = "interpolated-text";
          fragments = configurationFragmentsFor withTls;
          maximum_size_bytes = abilityTypes.limits.maxDocumentBytes;
        };
        mode = "0600";
        owner = resultOf "service-principal" "principal-name";
      };
    };
    serviceRequest = serviceManagement.forService {
      featureContributions = [
        (serviceManagement.featureContribution {
          key = "linux_isolation";
          requirementAlias = "linux-service-isolation";
          description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
          interface = "aos.platform.linux.service-isolation";
          abi = 1;
          parameters = {
            allow_privilege_escalation = false;
            ambient_capabilities = [];
            capability_bounds = {
              kind = "restricted";
              capabilities = [];
            };
            control_group_delegation = false;
            control_group_access = "read-only";
            device_namespace = "shared";
            kernel_clock_mutation = false;
            kernel_hostname_mutation = false;
            kernel_log_access = false;
            kernel_module_access = false;
            kernel_tunable_access = false;
            lock_personality = true;
            memory_write_execute = false;
            namespace_isolation = [];
            network_address_families = ["ipv4" "ipv6" "unix"];
            oom_score_adjust = 0;
            permit_realtime = false;
            permit_suid_sgid = false;
            process_visibility = "all";
            security_label = "aos-pkg-openldap";
            syscall_architectures = [];
            syscall_allow = [];
            syscall_deny = [];
            syscall_profile = "system-service";
            user_namespace_ownership = "none";
          };
        })
      ];
      inherit serviceTypes;
      consumerInstance = "openldap";
      declaration = {
        service = "main";
        enabled = true;
        lifecycle = {
          description = "OpenLDAP directory server";
          execution_model = "foreground";
          environment_files = [];
          condition = [];
          pre_start = [
            (command "sbin/slaptest" [
              "-u"
              "-f"
              (resultOf "server-configuration" "planned-path")
            ])
          ];
          start = [
            (command "libexec/slapd" [
              "-d"
              "0"
              "-f"
              (resultOf "server-configuration" "planned-path")
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
          after = [(resultOf "network-readiness" "readiness-resource")];
          before = [];
          requires = [];
          wants = [(resultOf "network-readiness" "readiness-resource")];
        };
        credentials =
          if withTls
          then {
            views = builtins.map (credential: {
              inherit (credential) name;
              inherit (credential.reference) encrypted;
              reference = resultOf "credential-${credential.name}" "credential-path";
              optional = false;
            }) (builtins.filter (credential: credential.name != "root-password") credentials);
          }
          else null;
        configuration.views = [
          {
            name = "server";
            source = resultOf "server-configuration" "planned-path";
            optional = false;
          }
        ];
        storage.mounts = [
          {
            name = "data";
            source = resultOf "data-view" "storage-path";
            access = "read-write";
          }
          {
            name = "runtime";
            source = resultOf "runtime-storage" "storage-path";
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
          principal = resultOf "service-principal" "principal-name";
          primary_group = resultOf "service-group" "group-name";
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
    };
  in [
    persistentStorage
    runtimeStorage
    dataView
    group
    principal
    networkReadiness
    credentialRequests
    configurationRequest
    serviceRequest
  ];
in {
  options.openldap = {
    enable = mkOption {
      type = abilityTypes.boolean;
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
        type = abilityTypes.boolean;
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
        type = abilityTypes.enum ["allow" "demand" "never" "try"];
        default = "demand";
        description = "Client-certificate verification policy applied to TLS sessions.";
      };
    };
  };

  config = lib.mkMerge (
    [
      {
        assertions = [
          {
            assertion =
              !cfg.enable
              || serviceManagement.credentialReferenceConfigured cfg.rootPassword;
            message = "openldap.enable requires an openldap.rootPassword credential reference";
          }
          {
            assertion =
              !cfg.tls.enable
              || builtins.all serviceManagement.credentialReferenceConfigured [
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
      }
      (lib.mkIf cfg.enable {aos.abilities.instances.openldap = {};})
    ]
    ++ builtins.map
    (withTls:
      lib.mkIf
      (cfg.enable && cfg.tls.enable == withTls)
      (lib.mkMerge (
        builtins.map
        (fragment: {aos.abilities = fragment;})
        (abilityFragmentsFor withTls)
      )))
    [false true]
  );
}
