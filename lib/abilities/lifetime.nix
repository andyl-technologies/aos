##! Shared ordering for ability resource and output lifetimes.
let
  # Later values may be retained by earlier-lived consumers.
  values = ["attempt" "transaction" "instance" "persistent"];
  rank = builtins.listToAttrs (builtins.genList (index: {
    name = builtins.elemAt values index;
    value = index;
  }) (builtins.length values));
in {
  inherit values;

  outlivesOrEquals = output: recipient:
    rank.${output} >= rank.${recipient};

  longest = current: candidate:
    if rank.${candidate} > rank.${current}
    then candidate
    else current;
}
