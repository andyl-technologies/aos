##! Portable native configuration files with durable ownership receipts.
{
  mkDerivation,
  python3,
  bash,
  service-management,
}:
mkDerivation {
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
  runtimeDeps = [python3 bash];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin" "$out/libexec"
        cp ${./_aos-configuration-provider/aos_configuration.py} "$out/libexec/aos_configuration.py"
        cp ${./_aos-configuration-provider/handler.py} "$out/libexec/handler.py"
        cat > "$out/bin/aos-configuration-provider" << EOF
        #!${bash}/bin/bash
        # The initrd store can be writable; imports must never change its NAR.
        exec "${python3}/bin/python3" -B "$out/libexec/handler.py" "\$@"
        EOF
        chmod +x "$out/bin/aos-configuration-provider"
      '';
    }
  ];
  meta.mainProgram = "aos-configuration-provider";
  meta.description = "Durable portable configuration file reconciliation";
}
