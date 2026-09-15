##! Restricted stock-Nix ability evaluator fixture.
let
  evaluate = arguments:
    if arguments.mode == "ok"
    then {inherit (arguments) enabled;}
    else if arguments.mode == "environment"
    then {observed = builtins.getEnv "AOS_ABILITY_EVALUATOR_SECRET";}
    else if arguments.mode == "host-file"
    then {observed = builtins.readFile "/etc/hostname";}
    else if arguments.mode == "outside-store"
    then {observed = builtins.readFile arguments.outside_path;}
    else if arguments.mode == "network"
    then {
      observed = builtins.fetchurl {
        url = "https://example.invalid/aos-ability-evaluator";
        sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      };
    }
    else if arguments.mode == "time"
    then {observed = builtins.currentTime;}
    else if arguments.mode == "path-result"
    then {observed = ./.;}
    else if arguments.mode == "context-result"
    then {observed = "${./.}";}
    else if arguments.mode == "function-result"
    then {observed = value: value;}
    else if arguments.mode == "derivation-result"
    then {
      observed = derivation {
        name = "aos-ability-forbidden-result";
        system = arguments.ifd_system;
        builder = arguments.builder;
      };
    }
    else if arguments.mode == "ifd"
    then let
      candidate = derivation {
        name = "aos-ability-forbidden-ifd";
        system = arguments.ifd_system;
        builder = arguments.builder;
      };
    in
      if candidate.drvPath != arguments.ifd_derivation
      then throw "IFD fixture derivation identity mismatch"
      else import candidate
    else if arguments.mode == "native-exec"
    then {observed = builtins.exec;}
    else if arguments.mode == "native-import"
    then {observed = builtins.importNative;}
    else if arguments.mode == "large-output"
    then {observed = builtins.concatStringsSep "" (builtins.genList (_: "0123456789abcdef") 1024);}
    else if arguments.mode == "slow"
    then {observed = builtins.foldl' (count: _: count + 1) 0 (builtins.genList (value: value) 2000000);}
    else if arguments.mode == "non-ascii-key"
    then {"é" = 1;}
    else if arguments.mode == "unsafe-integer"
    then {observed = 9007199254740992;}
    else throw "unknown evaluator fixture mode";
in {
  compose = evaluate;
  transition = evaluate;
}
