##! Builds the native install fixture shared by container lifecycle tests.
{pkgs}:
pkgs.mkDerivation {
  pname = "container-runtime-tool";
  version = "1.0.0";
  src = null;
  buildDeps = [pkgs.bash pkgs.coreutils];
  platformSupport = {
    build = [{os = ["linux"];}];
    host = [{os = ["linux"];}];
    target = [];
    role = "public-package";
  };
  meta = {
    description = "Container runtime install fixture";
    license = "MIT";
    maintainers = ["container-test@example.invalid"];
  };
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        printf '%s\n' \
          '#!${pkgs.bash}/bin/bash' \
          'printf "container-runtime-tool 1.0.0\\n"' \
          > "$out/bin/container-runtime-tool"
        chmod 0555 "$out/bin/container-runtime-tool"
      '';
    }
  ];
}
