##! Source cycle fixture; the back edge must terminate.
{...}: {
  imports = [./cycle-a.nix];
  importVisits = ["cycle-b"];
}
