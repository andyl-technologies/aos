##! Merges source-built OpenTofu providers into one filesystem mirror.
#
# The mirror carries a CLI configuration that installs exactly the mirrored
# providers from the store and never contacts a registry for them:
#
# ```text
# $out/share/opentofu/plugins/   unpacked filesystem mirror
# $out/share/opentofu/tofurc     select with TF_CLI_CONFIG_FILE
# ```
{
  lib,
  mkDerivation,
}: {
  pname ? "opentofu-provider-mirror",
  version,
  providers,
  description ? "Filesystem mirror of source-built OpenTofu providers",
  passthru ? {},
  checks ? null,
  qualification ? null,
  # Published mirrors declare their platform policy; private ones may omit it.
  platformSupport ? null,
}: let
  sources = map (provider: provider.passthru.provider.source) providers;
  quotedSources = lib.concatMapStringsSep ", " (source: ''"${source}"'') sources;
in
  mkDerivation ({
      inherit pname version passthru;
      src = null;
      runtimeDeps = providers;

      phases = [
        {
          name = "install";
          script = ''
            plugins="$out/share/opentofu/plugins"
            mkdir -p "$plugins"

            # Link each provider's platform directory. OpenTofu records the
            # resolved path, so lock-file hashes match the provider package.
            ${lib.concatMapStrings (provider: ''
                for platformDir in ${provider}/share/opentofu/plugins/*/*/*/*/*; do
                  relative="''${platformDir#${provider}/share/opentofu/plugins/}"
                  mkdir -p "$plugins/$(dirname "$relative")"
                  ln -s "$platformDir" "$plugins/$relative"
                done
              '')
              providers}

            cat > "$out/share/opentofu/tofurc" <<EOF
            provider_installation {
              filesystem_mirror {
                path    = "$plugins"
                include = [${quotedSources}]
              }
              direct {
                exclude = [${quotedSources}]
              }
            }
            EOF
          '';
        }
      ];

      meta = {
        inherit description;
        homepage = "https://opentofu.org/docs/cli/config/config-file/#provider-installation";
        license = "MPL-2.0";
      };
    }
    // lib.optionalAttrs (checks != null) {inherit checks;}
    // lib.optionalAttrs (qualification != null) {inherit qualification;}
    // lib.optionalAttrs (platformSupport != null) {inherit platformSupport;})
