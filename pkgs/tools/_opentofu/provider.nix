##! Builds one OpenTofu provider plugin from source in mirror layout.
#
# The output holds the provider in OpenTofu's unpacked filesystem-mirror
# layout, so one or more providers can be merged into a mirror directory:
#
# ```text
# $out/share/opentofu/plugins/
#   registry.opentofu.org/<namespace>/<type>/<version>/<os>_<arch>/
#     terraform-provider-<type>_v<version>
# ```
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  opentofu,
}: {
  # Provider type as written in `required_providers`, for example "null".
  type,
  version,
  # Upstream source repository in owner/name form.
  repository,
  hash,
  modulesHash,
  namespace ? "hashicorp",
  hostname ? "registry.opentofu.org",
  description,
  homepage ? "https://search.opentofu.org/provider/${namespace}/${type}",
  license ? "MPL-2.0",
  ldflags ? "-s -w",
  goTestFlags ? "./...",
  doCheck ? true,
  # Extra commands that provider tests execute.
  checkInputs ? [],
  # Tests that cannot run offline, as {file, test, reason} records. Each is
  # skipped in its source so every other test still runs.
  skippedTests ? [],
}: let
  src = fetchurl {
    name = "terraform-provider-${type}-${version}.tar.gz";
    urls = ["https://github.com/${repository}/archive/refs/tags/v${version}.tar.gz"];
    inherit hash;
  };

  executable = "terraform-provider-${type}_v${version}";
  providerDir = "share/opentofu/plugins/${hostname}/${namespace}/${type}/${version}";
in
  mkGoPackage {
    pname = "opentofu-provider-${type}";
    inherit version src ldflags goTestFlags doCheck;

    goModules = fetchGoModules {
      inherit src;
      name = "opentofu-provider-${type}-go-modules";
      hash = modulesHash;
    };
    goOutput = executable;

    # Provider tests drive a real CLI through terraform-plugin-testing, which
    # otherwise downloads Terraform. Run them against the source-built tofu.
    buildDeps = [opentofu] ++ checkInputs;
    postPatch =
      lib.concatMapStrings (skipped: ''
        sed -i '/^func ${skipped.test}(t \*testing.T) {$/a\\tt.Skip("${skipped.reason}")' ${skipped.file}
        grep -q 't.Skip("${skipped.reason}")' ${skipped.file}
      '')
      skippedTests;
    preBuild = ''
      export HOME="$TMPDIR/home"
      mkdir -p "$HOME"
      export TF_ACC_TERRAFORM_PATH=${opentofu}/bin/tofu
      export TF_ACC_PROVIDER_HOST=${hostname}
    '';

    # OpenTofu discovers mirrored providers by target directory name. Ask the
    # Go toolchain for the platform it compiled for so cross builds land in
    # the matching directory.
    postInstall = ''
      platform="$(go env GOOS)_$(go env GOARCH)"
      mkdir -p "$out/${providerDir}/$platform" "$out/share/licenses/opentofu-provider-${type}"
      mv "$out/bin/${executable}" "$out/${providerDir}/$platform/"
      rmdir "$out/bin"
      cp LICENSE "$out/share/licenses/opentofu-provider-${type}/"
    '';

    passthru.provider = {
      inherit type version namespace hostname;
      source = "${hostname}/${namespace}/${type}";
    };

    meta = {
      inherit description homepage license;
    };
  }
