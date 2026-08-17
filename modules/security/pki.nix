##! modules/security/pki.nix — System-wide CA trust store (/etc/ssl)
##!
##! Installs a bundle of trusted CA certificates at the conventional
##! /etc/ssl/certs/ca-certificates.crt (plus Debian- and Fedora-compatible
##! paths) so that TLS clients — gnutls (chrony NTS), OpenSSL, curl — can
##! verify peer certificates against a single, operator-extensible trust
##! store. Without this AOS ships no runtime CA trust at all and every TLS
##! verification fails.
##!
##! Mirrors NixOS's `security.pki` (nixos/modules/security/ca.nix): the
##! Mozilla bundle from pkgs/networking/ca-certificates.nix is the base, and
##! operators can graft additional roots (e.g. an internal CA for an in-fleet
##! NTS server or a private registry) via `certificateFiles`/`certificates`
##! without rebuilding any package.
{
  config,
  pkgs,
  lib,
  provenance,
  ...
}: let
  cfg = config.aos.security.pki;

  mozillaBundle = "${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt";
  hasExtras = cfg.certificateFiles != [] || cfg.certificates != [];

  # Inline PEM strings are materialized to a file so they can be
  # concatenated alongside the file-based roots. Only forced when set. A
  # `destination` is required so the output is a file at a known subpath
  # (an empty destination would make $out a directory).
  inlineCerts = pkgs.writeTextFile {
    name = "aos-extra-ca-certificates";
    destination = "/extra-ca-certificates.pem";
    text = lib.concatStringsSep "\n" cfg.certificates + "\n";
  };

  sources =
    [mozillaBundle]
    ++ cfg.certificateFiles
    ++ lib.optional (cfg.certificates != []) "${inlineCerts}/extra-ca-certificates.pem";

  # With no operator extras, use the package bundle directly (no rebuild).
  # Otherwise concatenate the Mozilla roots with the extra certificates.
  # runCommand pre-creates $out as a directory, so the bundle lives at a
  # subpath (mirroring the ca-certificates package layout).
  builtCaBundle =
    if !hasExtras
    then mozillaBundle
    else "${pkgs.runCommand "aos-ca-certificates" {} ''
      mkdir -p "$out/etc/ssl/certs"
      cat ${lib.concatMapStringsSep " " builtins.toString sources} \
        > "$out/etc/ssl/certs/ca-certificates.crt"
    ''}/etc/ssl/certs/ca-certificates.crt";

  # Stage 2 cannot invoke the builders above. Preserve the exact ordered
  # concatenation as pure manifest data instead: the Mozilla and file-backed
  # roots remain authenticated store-file references, while inline roots are
  # carried byte-for-byte. The Rust materializer validates every part as a
  # certificate-only PEM stream before publishing the generation.
  runtimeBundle =
    [
      {source = mozillaBundle;}
    ]
    ++ builtins.map (source: {source = builtins.toString source;}) cfg.certificateFiles
    ++ builtins.map (text: {text = text + "\n";}) cfg.certificates;

  configuredOwners = lib.unique (builtins.filter
    (owner: owner != "@base")
    [
      (provenance.ownerOfOption ["aos" "security" "pki" "certificateFiles"])
      (provenance.ownerOfOption ["aos" "security" "pki" "certificates"])
    ]);
  runtimeBundleOwner =
    if configuredOwners == []
    then "@base"
    else if builtins.length configuredOwners == 1
    then builtins.head configuredOwners
    else throw "runtime CA bundle depends on multiple non-image owners: ${lib.concatStringsSep ", " configuredOwners}";

  # Consumers should always use the stable runtime path. In particular, this
  # prevents forcing builtCaBundle from an otherwise pure stage-2 evaluation.
  caBundle = "/etc/ssl/certs/ca-certificates.crt";
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
    (lib.mkIf cfg.enable {
      # Canonical NixOS/Debian/Arch path, plus the Debian ca-bundle.crt and
      # Fedora/CentOS pki/tls compatibility aliases, matching NixOS.
      environment.etc."ssl/certs/ca-certificates.crt" = {
        source = builtCaBundle;
        runtimeCertificateBundle =
          if hasExtras
          then runtimeBundle
          else null;
      };
      environment.etc."ssl/certs/ca-bundle.crt" = {
        source = builtCaBundle;
        runtimeCertificateBundle =
          if hasExtras
          then runtimeBundle
          else null;
      };
      environment.etc."pki/tls/certs/ca-bundle.crt" = {
        source = builtCaBundle;
        runtimeCertificateBundle =
          if hasExtras
          then runtimeBundle
          else null;
      };

      # OpenSSL- and curl-based tools honor these in login sessions; gnutls
      # uses its compiled default trust store, which pkgs/security/gnutls.nix
      # points at the canonical /etc path below.
      environment.sessionVariables = {
        SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        NIX_SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
      };
    })
    {
      aos.security.pki = {
        inherit caBundle;
        _runtimeBundleOwner = runtimeBundleOwner;
      };
    }
  ];
}
