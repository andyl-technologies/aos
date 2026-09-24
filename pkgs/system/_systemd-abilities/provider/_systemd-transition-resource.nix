##! Selects changes for one controller's resource kind within a shared provider.
resourceKind: context: change: let
  snapshot =
    if change.kind == "remove"
    then context.before
    else context.after;
in
  snapshot
  != null
  && builtins.any (resource:
    resource.resource == change.resource && resource.kind == resourceKind)
  snapshot.resources
