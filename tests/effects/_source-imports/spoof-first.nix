##! Authored diagnostic labels must not determine source identity.
{...}: {
  _file = "same-authored-file.nix";
  importVisits = ["first"];
}
