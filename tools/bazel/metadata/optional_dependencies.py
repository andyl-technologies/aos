"""Specializes optional library edges alongside reviewed Cargo feature units.

Feature lists alone do not describe a Cargo unit: disabling a feature can also
remove an optional dependency. These helpers read the source manifest's feature
activation rules and prune only explicit library dependency labels. Build-script
dependencies belong to a separate Cargo unit and remain untouched.
"""

import ast
import json


def inactive_optional_dependencies(manifest, features):
    """Returns optional normal-dependency aliases disabled by these features.

    Target-specific normal dependencies participate in the same feature
    activation graph. An alias required by any target is retained; platform
    selection remains the generated BUILD file's responsibility. Features may
    reference build dependencies, but their edges are never selected for removal.
    """
    targets = list(manifest.get("target", {}).values())
    normal_sections = [manifest.get("dependencies", {})]
    normal_sections.extend(target.get("dependencies", {}) for target in targets)
    normal = {}
    for section in normal_sections:
        for alias, specification in section.items():
            is_optional = isinstance(specification, dict) and specification.get("optional", False)
            normal.setdefault(alias, []).append(is_optional)

    declarations = {alias: list(settings) for alias, settings in normal.items()}
    for scope in [manifest, *targets]:
        for kind in ["build-dependencies", "dev-dependencies"]:
            for alias, specification in scope.get(kind, {}).items():
                is_optional = isinstance(specification, dict) and specification.get("optional", False)
                declarations.setdefault(alias, []).append(is_optional)

    optional = {alias for alias, settings in declarations.items() if any(settings)}
    removable = {alias for alias, settings in normal.items() if all(settings)}
    definitions = manifest.get("features", {})
    explicit_dependencies = {item[4:] for items in definitions.values() for item in items if item.startswith("dep:")}
    implicit = optional - explicit_dependencies
    active = set()
    visited = set()
    pending = list(features)
    while pending:
        feature = pending.pop()
        if feature in visited:
            continue
        visited.add(feature)

        if feature.startswith("dep:"):
            alias = feature[4:]
            if alias not in optional:
                raise ValueError("feature references an unknown optional dependency: " + feature)
            active.add(alias)
        elif "/" in feature:
            alias, _, dependency_feature = feature.partition("/")
            weak = alias.endswith("?")
            alias = alias.removesuffix("?")
            if alias not in declarations or not dependency_feature or "/" in dependency_feature:
                raise ValueError("invalid dependency feature reference: " + feature)
            if not weak:
                active.add(alias)
        elif feature in definitions:
            pending.extend(definitions[feature])
        elif feature in implicit:
            active.add(feature)
        else:
            raise ValueError("unknown Cargo feature: " + feature)

    return removable - active


def prune_library_dependencies(rendered, labels):
    """Removes declared disabled labels from library edges and alias mappings.

    Every requested label must occur in a literal dependency list. Strings in
    source globs, environment values, and build-script rules are preserved.
    Unsupported dynamic dependency expressions fail instead of being guessed.
    """
    labels = set(labels)
    if not labels:
        return rendered

    lines = rendered.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def span(node):
        return offsets[node.lineno - 1] + node.col_offset, offsets[node.end_lineno - 1] + node.end_col_offset

    replacements = []
    removed = set()
    for statement in ast.parse(rendered).body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            continue
        call = statement.value
        if not isinstance(call.func, ast.Name) or call.func.id not in {"rust_library", "rust_proc_macro"}:
            continue

        for keyword in call.keywords:
            if keyword.arg in {"deps", "proc_macro_deps"}:
                for node in ast.walk(keyword.value):
                    if not isinstance(node, ast.List):
                        continue
                    selected = [element.value for element in node.elts
                                if isinstance(element, ast.Constant) and element.value in labels]
                    if not selected:
                        continue
                    if any(not isinstance(element, ast.Constant) or not isinstance(element.value, str)
                           for element in node.elts):
                        raise ValueError("optional dependencies require literal label lists")
                    remaining = [element.value for element in node.elts if element.value not in labels]
                    replacements.append((*span(node), json.dumps(remaining)))
                    removed.update(selected)
            elif keyword.arg == "aliases":
                for node in ast.walk(keyword.value):
                    if not isinstance(node, ast.Dict):
                        continue
                    selected = [key.value for key in node.keys
                                if isinstance(key, ast.Constant) and key.value in labels]
                    if not selected:
                        continue
                    try:
                        aliases = ast.literal_eval(node)
                    except (ValueError, TypeError) as error:
                        raise ValueError("optional dependencies require literal alias mappings") from error
                    remaining = {key: value for key, value in aliases.items() if key not in labels}
                    replacements.append((*span(node), json.dumps(remaining)))

    if removed != labels:
        raise ValueError("disabled optional dependency labels are absent: " + repr(sorted(labels - removed)))
    for start, end, replacement in sorted(replacements, reverse=True):
        rendered = rendered[:start] + replacement + rendered[end:]
    return rendered
