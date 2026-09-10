# Selects the ordinary reference closure rooted at one exported store path.

def canonical_store_path:
  type == "string"
  and test("^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+$");

def valid_export_graph($root):
  ([.[].path] | length) == ([.[].path] | unique | length)
  and ([.[] | select(.path == $root)] | length) == 1
  and ([.[].path] as $paths | all(.[];
    (.path | canonical_store_path)
    and (.narHash | type == "string")
    and (.narSize | type == "number")
    and (.references | type == "array")
    and all(.references[];
      type == "string"
      and (. as $reference | $paths | index($reference) != null)
    )
  ));

def reachable_from($root; $members):
  def visit($all):
    . as $seen
    | ($seen + [$all[]
        | select(.path as $path | $seen | index($path))
        | .references[]] | unique) as $next
    | if $next == $seen
      then $seen
      else $next | visit($all)
      end;
  [$root] | visit($members);

. as $members
| if valid_export_graph($root)
  then reachable_from($root; $members) as $reachable
    | $members[]
    | select(.path as $path | $reachable | index($path))
  else error("ability closure export graph is malformed or incomplete")
  end
