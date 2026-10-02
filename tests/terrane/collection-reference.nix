{pkgs}:
pkgs.mkDerivation {
  pname = "terrane-collection-reference-generator";
  version = "0.1.0";
  src = null;
  buildDeps = [pkgs.python3];
  phases = [
    {
      name = "check";
      script = ''
        mkdir -p "$out"
        python3 ${./collection_vectors.py} --self-check > "$out/result"
        python3 ${./collection_vectors.py} --emit > "$out/reference.md"
      '';
    }
  ];
}
