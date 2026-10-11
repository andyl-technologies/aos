##! Runtime projection removes engine annotations while retaining artifact contexts.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = builtins.toFile "native-provenance-payload" "retained artifact";
  evaluated = lib.evalModules {
    inherit lib;
    modules = [];
    packageModules = [
      {
        name = "fixture";
        module = {
          options.aos.example = lib.mkOption {
            type = lib.types.str;
            default = "${payload}/value";
          };
        };
      }
    ];
  };
  annotated = evaluated.config.aos.example;
  projected = evaluated._withoutProvenance {nested = [{value = annotated;}];};
  clean = (builtins.head projected.nested).value;
  payloadPath = builtins.unsafeDiscardStringContext payload;
in {
  markerPresentBeforeProjection = assert builtins.length (builtins.attrNames (builtins.getContext annotated)) > 1; true;
  realArtifactPreserved = assert builtins.attrNames (builtins.getContext clean) == [payloadPath]; true;
  valueUnchanged = assert clean == annotated; true;
  repeatedProjectionStable = assert builtins.getContext (evaluated._withoutProvenance clean) == builtins.getContext clean; true;
}
