##! Checks additional type predicates through actual option merging.
{lib}: let
  positive = lib.types.addCheck lib.types.int (value: value > 0);
  evaluate = declaration: definition:
    (lib.evalModules {
      modules = [
        {options.value = lib.mkOption declaration;}
        {config.value = definition;}
      ];
    }).config.value;
  rejects = value: !(builtins.tryEval (builtins.deepSeq value value)).success;

  invalidDefault =
    (lib.evalModules {
      modules = [
        {
          options.value = lib.mkOption {
            type = positive;
            default = 0;
          };
        }
      ];
    }).config.value;
  nested = lib.types.submodule {
    options.count = lib.mkOption {type = positive;};
  };
in
  evaluate {type = positive;} 42
  == 42
  && rejects (evaluate {type = positive;} 0)
  && rejects (evaluate {type = positive;} "42")
  && rejects invalidDefault
  && evaluate {type = lib.types.listOf positive;} [1 2] == [1 2]
  && rejects (evaluate {type = lib.types.listOf positive;} [1 0])
  && (evaluate {type = nested;} {count = 2;}).count == 2
  && rejects (evaluate {type = nested;} {count = 0;})
