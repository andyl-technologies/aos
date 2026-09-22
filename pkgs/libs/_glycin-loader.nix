##! Build an individual Glycin loader process and format registration.
{
  mkCargoPackage,
  callPackage,
  buildPackages,
  stdenv,
  libseccomp,
  loaderName,
  loaderDeps ? [],
}: let
  sources = callPackage ./_glycin-sources.nix {};
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = loaderName;
    inherit (sources) version src cargoDeps;
    buildDeps = [buildPackages.pkg-config];
    runtimeDeps = [libseccomp] ++ loaderDeps;
    cargoFlags = "-p ${loaderName}";
    cargoTestFlags = "-p ${loaderName}";
    doCheck = !stdenv.isCross;

    cargoEnv = {
      GIT_DESCRIBE = "";
    };

    postInstall = ''
      # Keep the external loader as its own process. The registration has no
      # localized fields; replace only its executable placeholder.
      mkdir -p "$out/libexec/glycin-loaders/2+" "$out/share/glycin-loaders/2+/conf.d"
      mv "$out/bin/${loaderName}" "$out/libexec/glycin-loaders/2+/"
      rmdir "$out/bin"
      sed "s|@EXEC@|$out/libexec/glycin-loaders/2+/${loaderName}|g" \
        glycin-loaders/${loaderName}/${loaderName}.conf \
        > "$out/share/glycin-loaders/2+/conf.d/${loaderName}.conf"
      mkdir -p "$out/share/licenses/${loaderName}"
      cp LICENSE* "$out/share/licenses/${loaderName}/"
    '';

    meta = {
      description = "Glycin ${loaderName} loader process and format registrations";
      homepage = "https://gitlab.gnome.org/GNOME/glycin";
      license = "MPL-2.0 OR LGPL-2.1-or-later";
    };
  }
