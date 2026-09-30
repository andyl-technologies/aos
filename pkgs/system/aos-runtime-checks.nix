##! Native interface for package-owned runtime test specifications.
{mkDerivation}:
mkDerivation {
  platformSupport = {
    build = [{os = ["linux" "darwin"];}];
    host = [{os = ["linux" "darwin"];}];
    target = [];
    role = "public-package";
  };
  pname = "aos-runtime-checks";
  version = "1";
  module = ./_aos-runtime-checks;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
      '';
    }
  ];
  meta.description = "Typed runtime VM check specifications";
}
