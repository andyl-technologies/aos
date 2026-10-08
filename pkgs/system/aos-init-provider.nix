##! Portable installation of retained initial process configuration.
{
  mkDerivation,
  init-system,
  aos-configuration-provider,
}:
mkDerivation {
  pname = "aos-init-provider";
  version = "1";
  platformSupport = {
    build = [{os = ["linux" "darwin"];}];
    host = [{os = ["linux" "darwin"];}];
    target = [];
    role = "public-package";
  };
  module = ./_aos-init-provider;
  moduleDeps = [init-system aos-configuration-provider];
  phases = [
    {
      name = "install";
      script = ''mkdir -p "$out"'';
    }
  ];
  meta.description = "Initial process configuration prepared without mutating a live process";
}
