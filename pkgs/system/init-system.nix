##! Portable contract for preparing the next startup command.
{mkDerivation}:
mkDerivation {
  pname = "init-system";
  version = "1";
  platformSupport = {
    build = [{os = ["linux" "darwin"];}];
    host = [{os = ["linux" "darwin"];}];
    target = [];
    role = "public-package";
  };
  module = ./_init-system;
  phases = [
    {
      name = "install";
      script = ''mkdir -p "$out"'';
    }
  ];
  meta.description = "Typed initial process installation contract";
  meta.license = "Apache-2.0";
}
