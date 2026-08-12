let
  values = builtins.genList (index: index + 1) 8;
in {
  manifest = {
    doubled = builtins.map (value: value * 2) values;
    lowerHalf = builtins.filter (value: value <= 4) values;
    sum = builtins.foldl' (total: value: total + value) 0 values;
  };
  optionWrites = [];
}
