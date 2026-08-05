let
  values = builtins.genList (i: (i + 1) * (i + 3)) 2048;
in
  builtins.foldl' (sum: value: sum + value) 0 values
