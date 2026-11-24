import Lean.Data.Json
import Std.Data.HashMap
import Sandbox

/-!
# `sandbox-model`

The executable reference model. `sandbox-model update INPUT` reads a store
graph and a sandbox's current roots, mounts, and desired roots, and prints the
target closure and the update procedure's actions, computed by the same
definitions the theorems are about.

```text
input:  {"graph": [{"path": P, "refs": [P, ...]}, ...],
         "roots": [P, ...], "mounted": [P, ...], "desired": [P, ...]}
output: {"target": [P, ...],
         "actions": [{"op": "addRoot" | "mount" | "unmount" | "dropRoot", "path": P}, ...]}
     or {"error": "closure" | "plan"}
```

A path missing from `graph` has no references. An implementation of the store
helper replays the checked-in vectors against its own planner and must
produce the same actions.
-/

open Lean Sandbox.Store

/-- One store path and its references. -/
structure Entry where
  path : String
  refs : List String

/-- One update request. -/
structure Input where
  graph : List Entry
  roots : List String
  mounted : List String
  desired : List String

def parseEntry (j : Json) : Except String Entry := do
  return { path := ← j.getObjValAs? String "path", refs := ← j.getObjValAs? (List String) "refs" }

def parseInput (j : Json) : Except String Input := do
  let graph ← j.getObjValAs? (List Json) "graph"
  return {
    graph := ← graph.mapM parseEntry
    roots := ← j.getObjValAs? (List String) "roots"
    mounted := ← j.getObjValAs? (List String) "mounted"
    desired := ← j.getObjValAs? (List String) "desired"
  }

/-- The reference graph the input describes. -/
def Input.toGraph (input : Input) : Graph String :=
  let refs : Std.HashMap String (List String) :=
    input.graph.foldl (fun refs entry => refs.insert entry.path entry.refs) {}
  { refs := fun p => refs.getD p [] }

/-- More expansion rounds than the input has distinct paths, which is always
enough for the closure to finish. -/
def Input.fuel (input : Input) : Nat :=
  input.graph.foldl (fun n entry => n + 1 + entry.refs.length) (input.desired.length + 1)

def actionJson : Action String → Json
  | .addRoot r => Json.mkObj [("op", Json.str "addRoot"), ("path", Json.str r)]
  | .mount p => Json.mkObj [("op", Json.str "mount"), ("path", Json.str p)]
  | .unmount p => Json.mkObj [("op", Json.str "unmount"), ("path", Json.str p)]
  | .dropRoot r => Json.mkObj [("op", Json.str "dropRoot"), ("path", Json.str r)]

/-- The target closure and the procedure's actions for one request. -/
def update (input : Input) : Json :=
  let g := input.toGraph
  match closure? g input.desired input.fuel with
  | none => Json.mkObj [("error", Json.str "closure")]
  | some target =>
    match procedure g input.roots input.mounted input.desired target with
    | none => Json.mkObj [("error", Json.str "plan")]
    | some acts =>
      Json.mkObj [("target", toJson target), ("actions", Json.arr (acts.map actionJson).toArray)]

def main (args : List String) : IO UInt32 := do
  match args with
  | ["update", path] =>
    let text ← IO.FS.readFile path
    match Json.parse text >>= parseInput with
    | .error message =>
      IO.eprintln s!"sandbox-model: {path}: {message}"
      return 2
    | .ok input =>
      IO.println (update input).pretty
      return 0
  | _ =>
    IO.eprintln "usage: sandbox-model update INPUT"
    return 2
