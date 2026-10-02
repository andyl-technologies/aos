##! Native manager-neutral service interface and shared service configuration.
{mkDerivation}:
mkDerivation {
  platformSupport = {
    build = [{os = ["linux" "darwin"];}];
    host = [{os = ["linux" "darwin"];}];
    target = [];
    role = "public-package";
  };
  pname = "service-management";
  version = "1";
  module = ./_service-management;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
      '';
    }
  ];
  meta.description = "Typed service lifecycle contracts and domain configuration";
}
