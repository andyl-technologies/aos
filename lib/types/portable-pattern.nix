##! Checks the regular-expression subset shared by Nix and runtime validators.
value: let
  maxPatternLength = 4096;
  characters =
    if builtins.isString value
    then builtins.genList (index: builtins.substring index 1 value) (builtins.stringLength value)
    else [];
  hasPair = first: second:
    builtins.any (index:
      builtins.elemAt characters index
      == first
      && builtins.elemAt characters (index + 1) == second)
    (builtins.genList (index: index) (builtins.length characters - 1));
  lexicalState =
    builtins.foldl' (
      state: character:
        if !state.valid
        then state
        else if state.escaped
        then {
          escaped = false;
          inherit (state) inClass;
          valid = builtins.elem character ["." "\\"];
        }
        else if character == "\\"
        then state // {escaped = true;}
        else if character == "[" && !state.inClass
        then state // {inClass = true;}
        else if character == "]" && state.inClass
        then state // {inClass = false;}
        else if !state.inClass && builtins.elem character ["^" "$"]
        then state // {valid = false;}
        else state
    ) {
      escaped = false;
      inClass = false;
      valid = true;
    }
    characters;
  portable =
    characters
    != []
    && builtins.match "[[:print:]]+" value != null
    && !(hasPair "(" "?")
    && !(hasPair "&" "&")
    && !(hasPair "~" "~")
    && !(hasPair "[" ".")
    && !(hasPair "[" "=")
    && lexicalState.valid
    && !lexicalState.escaped
    && !lexicalState.inClass;
  attempted =
    if portable && builtins.stringLength value <= maxPatternLength
    then builtins.tryEval (builtins.match value "")
    else {success = false;};
in
  if attempted.success
  then value
  else throw "String pattern must use the portable regular-expression subset and contain at most ${builtins.toString maxPatternLength} bytes"
