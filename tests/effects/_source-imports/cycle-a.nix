##! Source cycle fixture; each source contributes once.
{...}: {
  imports = [./cycle-b.nix];
  importVisits = ["cycle-a"];
}
