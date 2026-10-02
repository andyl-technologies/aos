##! Writes companion documents without introducing compiler payload references.
{
  bash,
  coreutils,
  system,
}: {
  name,
  text,
  destination,
}:
assert builtins.match "/.+" destination != null;
  builtins.derivation {
    inherit name system text destination;
    builder = "${bash}/bin/bash";
    args = [
      "--noprofile"
      "--norc"
      "-euc"
      ''
        target="$out$destination"
        ${coreutils}/bin/mkdir -p "$(${coreutils}/bin/dirname "$target")"
        ${coreutils}/bin/cp "$textPath" "$target"
      ''
    ];
    passAsFile = ["text"];
    preferLocalBuild = true;
    allowSubstitutes = false;
  }
