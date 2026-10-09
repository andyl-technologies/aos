##! Portable native configuration files with durable ownership receipts.
{
  mkAosCargoPackage,
  aosWorkspaceVendor,
  service-management,
}:
mkAosCargoPackage {
  pname = "aos-configuration-provider";
  version = "1";
  platformSupport = {
    build = [{os = ["linux" "darwin"];}];
    host = [{os = ["linux" "darwin"];}];
    target = [];
    role = "public-package";
  };
  module = ./_aos-configuration-provider;
  moduleDeps = [service-management];
  cargoDeps = aosWorkspaceVendor;
  cargoRoot = "crates";
  cargoFlags = "-p aos-activation-config-files";
  cargoTestFlags = "-p aos-activation-config-files";
  preBuild = ''
    mkdir -p "$out/bin"
    cc -std=c11 -O2 -Wall -Wextra -Werror \
      ${./_aos-configuration-provider/account-lookup.c} \
      -o "$out/bin/aos-account-lookup"
    export AOS_ACCOUNT_LOOKUP="$out/bin/aos-account-lookup"
  '';
  doCheck = true;
  runtimeDeps = [];
  meta.mainProgram = "aos-configuration-provider";
  meta.description = "Durable portable configuration file reconciliation";
  meta.license = "Apache-2.0";
}
