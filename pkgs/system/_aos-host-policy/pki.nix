##! Retains the system CA trust policy and native certificate lower inputs.
{
  config,
  lib,
  provenance,
  dependencies ? {},
  pkgs ? {},
  ...
}: let
  cfg = config.aos.security.pki;
  bundlePath = "/etc/ssl/certs/ca-certificates.crt";
  mozilla = "${dependencies.ca-certificates or pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt";
  fileSource = source: let
    path = builtins.toString source;
    root = sourceRoot path;
  in
    if lib.hasPrefix "/nix/store/" path
    then
      if builtins.getContext path != {}
      then path
      else builtins.appendContext path {${builtins.unsafeDiscardStringContext root} = {path = true;};}
    else "${source}";
  parts =
    [
      {
        kind = "store-file";
        path = mozilla;
      }
    ]
    ++ map (source: {
      kind = "store-file";
      path = fileSource source;
    })
    cfg.certificateFiles
    ++ map (text: {
      kind = "text";
      text = text + "\n";
    })
    cfg.certificates;
  sources = map (part: part.path) (builtins.filter (part: part.kind == "store-file") parts);
  sourceRoot = path: let
    matched = builtins.match "(/nix/store/[^/]+)(/.*)?" path;
  in
    if matched == null
    then throw "PKI certificate inputs must be immutable store files"
    else builtins.elemAt matched 0;
  owners = lib.unique (builtins.filter (owner: owner != "@base") [
    (provenance.ownerOfOption ["aos" "security" "pki" "certificateFiles"])
    (provenance.ownerOfOption ["aos" "security" "pki" "certificates"])
  ]);
  owner =
    if owners == []
    then "@base"
    else if builtins.length owners == 1
    then builtins.head owners
    else throw "runtime CA bundle depends on multiple non-image owners: ${lib.concatStringsSep ", " owners}";
  files = {
    "ssl/certs/ca-certificates.crt" = {
      kind = "certificate-bundle";
      inherit parts;
      mode = "0444";
    };
    "ssl/certs/ca-bundle.crt" = {
      kind = "symlink";
      target = "ca-certificates.crt";
    };
    "pki/tls/certs/ca-bundle.crt" = {
      kind = "symlink";
      target = "../../../ssl/certs/ca-certificates.crt";
    };
  };
in {
  options.aos.security.pki = {
    ## Install the system CA trust store to /etc/ssl.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Install the system-wide CA trust store under /etc/ssl. Enabled by
        default so TLS clients can verify server certificates out of the
        box; without it gnutls/OpenSSL/curl have no trust roots.
      '';
    };

    ## Extra trusted root certificate files (PEM), appended to the bundle.
    certificateFiles = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [];
      description = ''
        Additional PEM files of trusted root certificates, concatenated
        onto the Mozilla bundle to form /etc/ssl/certs/ca-certificates.crt.
        Use this to trust an internal CA — for example a private NTS or
        registry server. Example: `[ ./internal-ca.crt ]`.
      '';
    };

    ## Extra trusted roots as inline PEM strings.
    certificates = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Additional trusted root certificates as inline PEM strings,
        appended to the system bundle. Equivalent to `certificateFiles`
        for certs you would rather keep in configuration than in a file.
      '';
    };

    ## (Read-only) path to the assembled CA bundle.
    caBundle = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      description = ''
        (Read-only) path to the assembled CA bundle. Other modules may
        reference this to point a service at the system trust store.
      '';
    };

    _runtimeBundleOwner = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      internal = true;
      description = "Resolver-authenticated owner of the runtime CA bundle inputs.";
    };
  };

  config = lib.mkMerge [
    {
      aos.security.pki = {
        caBundle = bundlePath;
        _runtimeBundleOwner = owner;
      };
    }
    (lib.mkIf (cfg.enable && (config.aos.boot.stage or "host") == "host") {
      aos.configurationLower = {
        inherit files;
        ownership.files = lib.mapAttrs (_: _: owner) files;
        storePaths = lib.unique (map sourceRoot sources);
      };
      environment.sessionVariables = {
        SSL_CERT_FILE = bundlePath;
        NIX_SSL_CERT_FILE = bundlePath;
      };
    })
  ];
}
