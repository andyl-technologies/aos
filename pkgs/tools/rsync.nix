##! rsync — Fast incremental file transfer
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  openssl,
  zstd,
  lz4,
  bash,
  stdenv,
}: let
  version = "3.5.0";
in
  mkDerivation {
    pname = "rsync";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.samba.org/pub/rsync/src/rsync-${version}.tar.gz"
      ];
      hash = "sha256-x//R72U+mVQPZh5HywC3+crR7muXI5mxb5PWcmVuDTM=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [
        zlib
        openssl
        zstd
        lz4
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    abilities = ./_rsyncd/module.nix;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rsync-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-included-popt \
            --with-included-zlib=no \
            --disable-xxhash \
            --enable-zstd \
            --enable-lz4 \
            --disable-md2man
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            if [ -f "$out/bin/rsync-ssl" ]; then
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/rsync-ssl"
            fi
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "rsync — fast incremental file transfer";
      homepage = "https://rsync.samba.org/";
      license = "GPL-3.0-or-later";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: let
      serviceManagement = lib.abilities.interfaces.serviceManagement;
      environmentId = lib.abilities.environmentId {
        authority = "deployment";
        key = "rsyncd-test";
        stage = "host";
      };
      credentialProvider = lib.abilities.instanceId {
        environment = environmentId;
        key = "credential-provider";
      };
      credential = lib.abilities.resourceReference {
        interface = serviceManagement.interfaces.credentialDelivery.identity;
        resource = {
          provider = credentialProvider;
          key = "rsync-secrets";
        };
        operations = ["observe"];
        lifetime = "persistent";
      };
      evaluate = rsyncd:
        lib.evalModules {
          inherit lib;
          modules = [
            ../../modules/abilities/default.nix
            {
              options.assertions = lib.mkOption {
                type = lib.types.listOf lib.types.attrs;
                default = [];
                contributable = true;
              };
              aos.abilities.environment = builtins.removeAttrs environmentId ["_type"];
              inherit rsyncd;
            }
          ];
          packageModules = [
            {
              name = "rsync";
              module.imports = [./_rsyncd/module.nix];
            }
          ];
        };
      evaluated = evaluate {
        enable = true;
        modules.public = {};
      };
      authenticated = evaluate {
        enable = true;
        modules.private.authUsers = ["backup"];
        secrets.resource = credential;
      };
      invalid = evaluate {
        enable = true;
        modules.private.authUsers = ["backup"];
      };
      assertionsHold = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      requests = evaluated.config.aos.abilities.requests;
      authenticatedRequests = authenticated.config.aos.abilities.requests;
      configuration = requests."rsync:daemon-configuration".parameters;
      contractHolds =
        assertionsHold evaluated
        && assertionsHold authenticated
        && !assertionsHold invalid
        && configuration.source.kind == "interpolated-text"
        && !(lib.hasInfix "/var/lib/aos-pkg-rsyncd" (builtins.toJSON configuration))
        && !(lib.hasInfix "RSYNCD_CONFIG_GENERATION" (builtins.toJSON requests))
        && !(builtins.hasAttr "rsync:secrets-file" requests)
        && builtins.hasAttr "rsync:secrets-file" authenticatedRequests;
    in {
      version = testing.mkToolCheck {
        pname = "tool-rsync";
        tool = self;
        command = "rsync --version";
      };

      ability-module-contract =
        if contractHolds
        then
          pkgs.runCommand "rsyncd-ability-module-contract" {} ''
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          ''
        else throw "the rsyncd native ability checks failed";
    };
  }
