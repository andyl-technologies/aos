"""Constructs complete inert namespace and hierarchical index field tables.

The four finite graphs retain repeated graft occurrences, independent present
and missing predicates, genuine direct-Chunk content, and local route grammar.
Source and carrier recurrences are compared as mathematical fixture checks;
these checks do not qualify owning codecs, runtime performance or authority.
"""

from copy import deepcopy
import re

from index_vector_primitives import cbor, diagnostic, expanded, leaf, raw_digest


SOURCE = b"inert D-104 direct-chunk fixture\n"
ATTRIBUTE = "uid"
VALUE = 24
MIN_CHUNK = 262144
ACTIVE = {"property": 3, "attribute": 2, "tree": 1}


def file_entry(object_id, present):
    """Constructs a complete ordinary file with the required direct-Chunk tag."""
    result = {1: 1, 2: 0o644, 3: len(SOURCE), 4: [0, object_id]}
    if present:
        result[9] = {ATTRIBUTE: VALUE}
    return result


def row(object_id, route=None):
    """Transcribes terminal/forward Index fields without validating their role."""
    result = {1: 7, 14: [object_id]}
    if route is not None:
        result[9] = {"index.occurrences": route}
    return result


def owner_props(index_id):
    """Represents an exact owner-local binding plus ordinary index requirement."""
    return {
        "domain": "public", "index": [ATTRIBUTE],
        "index-roots": {"inherit": False, "value": {ATTRIBUTE: index_id.hex()}},
    }


def gap_props(gap_id):
    """Represents the sole property permitted on a gap-bearing primary root."""
    return {"index-gaps": {"inherit": False, "value": gap_id.hex()}}


class Candidates:
    """Retains ordinary field tables, manually encoded bytes and typed role claims."""

    def __init__(self, binary):
        self.binary = binary
        self.models = {}
        self.records = []
        self.by_digest = {}
        self.recipes = []
        self.object_id = raw_digest(binary, "terrane-chunk-v1", SOURCE)

    def add(self, name, role, model):
        """Assigns a registered Node identity only to a positive full Node."""
        wire = cbor(model)
        identity = raw_digest(self.binary, "terrane-node-v1", wire)
        descriptor = ["blake3", "terrane-node-v1", identity, len(wire)]
        if identity in self.by_digest:
            assert self.by_digest[identity] == model
        self.models[name] = model
        self.by_digest[identity] = model
        self.records.append({
            "name": name, "role_claim": role, "node_id": identity.hex(),
            "model": diagnostic(model), "wire_hex": wire.hex(),
            "preimage_hex": (b"terrane-node-v1\0" + wire).hex(),
            "descriptor": diagnostic(descriptor), "descriptor_wire_hex": cbor(descriptor).hex(),
            "full_entries": [
                {"key_hex": key.hex(), "entry": diagnostic(entry)}
                for key, entry in expanded(model)
            ],
            "construction_order": len(self.records),
        })
        return identity

    def recipe(self, name, owner, index):
        """Constructs detached recipe Q only after its completed owner is present."""
        assert owner in self.by_digest and index in self.by_digest
        model = {1: "index", 2: [owner], 3: {"attribute": ATTRIBUTE, "profile": "terrane-index/v1"}}
        wire = cbor(model)
        key = raw_digest(self.binary, "terrane-memo-v1", wire)
        self.recipes.append({
            "name": name, "model": diagnostic(model), "wire_hex": wire.hex(),
            "memo_lookup_key": key.hex(),
            "preimage_hex": (b"terrane-memo-v1\0" + wire).hex(),
            "owner_node_id": owner.hex(), "expected_result_node_id": index.hex(),
            "constructed_after_node_count": len(self.records),
            "identity_note": "Recipe lookup q; no Memo object or completed materialization is claimed.",
        })
        return key


def fixture(binary):
    """Builds acyclic positive graph tables before supplying detached recipes."""
    data = Candidates(binary)
    object_id = data.object_id
    pair = cbor(VALUE) + object_id
    empty = data.add("empty-ordinary", "ordinary namespace root", leaf([]))
    empty_index = data.add("empty-index", "empty primary with no gaps", leaf([]))
    assert empty == empty_index and cbor(leaf([])).hex() == "a201000280"

    present_child = data.add("child-present-route", "present route uid/24/O", leaf([
        (b"present", row(object_id)),
    ]))
    missing_child = data.add("child-missing-route", "missing route uid/O", leaf([
        (b"missing", row(object_id)),
    ]))
    child_gaps = data.add("child-gaps", "missing objects uid", leaf([
        (object_id, row(object_id, missing_child)),
    ]))
    child_index = data.add("child-primary", "primary uid", leaf([
        (pair, row(object_id, present_child)),
    ], gap_props(child_gaps)))
    child_source = data.add("child-source", "ordinary namespace root", leaf([
        (b"missing", file_entry(object_id, False)),
        (b"present", file_entry(object_id, True)),
    ], owner_props(child_index)))

    parent_present = data.add("parent-present-route", "present route uid/24/O", leaf([
        (b"left", row(object_id, present_child)),
        (b"right", row(object_id, present_child)),
    ]))
    parent_missing = data.add("parent-missing-route", "missing route uid/O", leaf([
        (b"left", row(object_id, missing_child)),
        (b"right", row(object_id, missing_child)),
    ]))
    parent_gaps = data.add("parent-gaps", "missing objects uid", leaf([
        (object_id, row(object_id, parent_missing)),
    ]))
    parent_index = data.add("parent-primary", "primary uid", leaf([
        (pair, row(object_id, parent_present)),
    ], gap_props(parent_gaps)))
    parent_source = data.add("parent-owner", "ordinary namespace root", leaf([
        (b"left", {1: 4, 6: child_source, 7: {"acl": [["reader-left", 1]]}}),
        (b"right", {1: 4, 6: child_source, 7: {"acl": [["reader-right", 1]]}}),
    ], owner_props(parent_index)))

    zero_route = data.add("zero-missing-route", "missing route uid/O", leaf([
        (b"missing", row(object_id)),
    ]))
    zero_gaps = data.add("zero-gaps", "missing objects uid", leaf([
        (object_id, row(object_id, zero_route)),
    ]))
    zero_index = data.add("zero-primary", "primary uid with zero candidates and nonempty G", leaf(
        [], gap_props(zero_gaps),
    ))
    zero_source = data.add("zero-owner", "ordinary namespace root", leaf([
        (b"missing", file_entry(object_id, False)),
    ], owner_props(zero_index)))

    # Every local key is valid; a flattened request path would exceed TREE-6.
    long_route = data.add("long-00-route", "present route uid/24/O", leaf([(b"end", row(object_id))]))
    long_index = data.add("long-00-primary", "primary uid without gaps", leaf([
        (pair, row(object_id, long_route)),
    ]))
    long_source = data.add("long-00-owner", "ordinary namespace root", leaf([
        (b"end", file_entry(object_id, True)),
    ], owner_props(long_index)))
    for depth in range(1, 18):
        local_key = b"x" * 255
        long_route = data.add(f"long-{depth:02}-route", "present route uid/24/O", leaf([
            (local_key, row(object_id, long_route)),
        ]))
        long_index = data.add(f"long-{depth:02}-primary", "primary uid without gaps", leaf([
            (pair, row(object_id, long_route)),
        ]))
        long_source = data.add(f"long-{depth:02}-owner", "ordinary namespace root", leaf([
            (local_key, {1: 4, 6: long_source}),
        ], owner_props(long_index)))

    owners = [
        ("child", child_source, child_index),
        ("repeated-grafts", parent_source, parent_index),
        ("zero-candidates", zero_source, zero_index),
        ("long-local-routes", long_source, long_index),
    ]
    for name, owner, index in owners:
        data.recipe(name, owner, index)
    return data, owners, empty


def local_path(key):
    """Checks local TREE path grammar without flattening graft-hop sequences."""
    components = key.split(b"/")
    if not key or len(key) > 4096 or b"\0" in key:
        raise ValueError("local route path width/zero byte")
    if any(not part or len(part) > 255 or part in (b".", b"..") for part in components):
        raise ValueError("local route path component")


def actual_object(entry):
    """Checks the actual fixture's file object follows existing direct-Chunk rules."""
    if entry.get(1) != 1 or entry.get(3) != len(SOURCE) or entry.get(4, [])[:1] != [0]:
        raise ValueError("actual source file size/tag")
    if len(entry[4]) != 2 or len(entry[4][1]) != 32 or entry[3] > MIN_CHUNK:
        raise ValueError("actual source file content width/minimum")
    return entry[4][1]


def source_occurrences(data, namespace, branch=(), hops=(), layers=()):
    """Walks source field tables independently of any I/P/G candidate table."""
    if namespace in branch or len(branch) > 64:
        raise ValueError("source active-branch cycle/depth")
    model = data.by_digest[namespace]
    root_layer = {"kind": "root", "node_id": namespace.hex(), "properties": diagnostic(model.get(3, {}))}
    result = []
    for key, entry in expanded(model):
        local_path(key)
        if entry[1] == 1:
            result.append({
                "hops": hops + (key,), "object": actual_object(entry),
                "value": cbor(entry[9][ATTRIBUTE]) if ATTRIBUTE in entry.get(9, {}) else None,
                "layers": layers + (root_layer,),
            })
        elif entry[1] == 4:
            override = {"kind": "graft override", "key_hex": key.hex(), "properties": diagnostic(entry.get(7, {}))}
            result.extend(source_occurrences(
                data, entry[6], branch + (namespace,), hops + (key,),
                layers + (root_layer, override),
            ))
        else:
            raise ValueError("unsupported source kind in this finite corpus")
    return result


def closed_row(entry, object_id, forwarding):
    """Checks closed contextual row fields; this is not a generic Entry decoder."""
    expected = {1, 14, 9} if forwarding else {1, 14}
    if set(entry) != expected or entry.get(1) != 7 or entry.get(14) != [object_id]:
        raise ValueError("closed row fields/type/singleton actual O")
    if forwarding:
        attrs = entry[9]
        if not isinstance(attrs, dict) or set(attrs) != {"index.occurrences"}:
            raise ValueError("forward pointer sole attribute")
        pointer = attrs["index.occurrences"]
        if not isinstance(pointer, bytes) or len(pointer) != 32:
            raise ValueError("forward pointer width")
        return pointer
    return None


def route_occurrences(data, model, namespace, object_id, value, branch=(), hops=(), layers=()):
    """Interprets local route tables against independently supplied source roots."""
    if namespace in branch or len(branch) > 64 or 3 in model:
        raise ValueError("route cycle/depth or forbidden properties")
    entries = expanded(model)
    if not entries:
        raise ValueError("empty continuation route")
    source_model = data.by_digest[namespace]
    source = dict(expanded(source_model))
    root_layer = {"kind": "root", "node_id": namespace.hex(), "properties": diagnostic(source_model.get(3, {}))}
    result = []
    for key, entry in entries:
        local_path(key)
        actual = source.get(key)
        if actual is None:
            raise ValueError("route points to absent source entry")
        if actual[1] == 1:
            closed_row(entry, object_id, False)
            if actual_object(actual) != object_id:
                raise ValueError("route terminal source O mismatch")
            inline = cbor(actual[9][ATTRIBUTE]) if ATTRIBUTE in actual.get(9, {}) else None
            if inline != value:
                raise ValueError("route terminal present/missing predicate mismatch")
            result.append({
                "hops": hops + (key,), "object": object_id, "value": value,
                "layers": layers + (root_layer,),
            })
        elif actual[1] == 4:
            pointer = closed_row(entry, object_id, True)
            override = {"kind": "graft override", "key_hex": key.hex(), "properties": diagnostic(actual.get(7, {}))}
            result.extend(route_occurrences(
                data, data.by_digest[pointer], actual[6], object_id, value,
                branch + (namespace,), hops + (key,), layers + (root_layer, override),
            ))
        else:
            raise ValueError("route target is neither file nor actual graft")
    return result


def binding(model, placement):
    """Checks the exact primary-only gap wrapper and absent-map convention."""
    if placement != "primary" or set(model) != {"index-gaps"}:
        raise ValueError("index-gaps property placement/sole map member")
    wrapper = model["index-gaps"]
    if not isinstance(wrapper, dict) or set(wrapper) != {"value", "inherit"}:
        raise ValueError("index-gaps exact wrapper")
    if wrapper["inherit"] is not False or not re.fullmatch(r"[0-9a-f]{64}", str(wrapper["value"])):
        raise ValueError("index-gaps false/lowercase Node hex")
    return bytes.fromhex(wrapper["value"])


def validate_primary(data, model, namespace, gaps_override=None):
    """Compares the entire finite carrier with source recurrence, including gaps."""
    expected = source_occurrences(data, namespace)
    actual = []
    for key, entry in expanded(model):
        if not 33 <= len(key) <= 4096 or key[:-32] != cbor(VALUE):
            raise ValueError("primary key complete registered uid value plus O")
        object_id = key[-32:]
        pointer = closed_row(entry, object_id, True)
        actual.extend(route_occurrences(data, data.by_digest[pointer], namespace, object_id, key[:-32]))
    gaps = None
    if 3 in model:
        pointer = binding(model[3], "primary")
        gaps = data.by_digest[pointer] if gaps_override is None else gaps_override
        if 3 in gaps or not expanded(gaps):
            raise ValueError("gap tree properties or empty bound G")
        for key, entry in expanded(gaps):
            if len(key) != 32:
                raise ValueError("gap key is not exactly O")
            route = closed_row(entry, key, True)
            actual.extend(route_occurrences(data, data.by_digest[route], namespace, key, None))
    if actual != sorted(expected, key=lambda item: (item["value"] is None, item["value"] or b"", item["object"], item["hops"])):
        raise ValueError("extra or omitted source recurrence occurrence/gap")
    return expected


def refuses(action):
    """Records a mathematical contextual refusal without claiming codec rejection."""
    try:
        action()
    except (ValueError, KeyError, TypeError) as error:
        return str(error)
    raise AssertionError("independent negative was accepted by mathematical fixture check")


def controls(data, owners, empty):
    """Assembles malformed canonical field models outside any rejecting encoder."""
    names = {name: (owner, index) for name, owner, index in owners}
    parent, parent_index = names["repeated-grafts"]
    child, _ = names["child"]
    object_id = data.object_id
    primary = data.by_digest[parent_index]
    route_id = primary[2][0][2][9]["index.occurrences"]
    results = []

    def add(name, model, action, scope):
        results.append({
            "name": name, "scope": scope, "model": diagnostic(model),
            "wire_hex": cbor(model).hex(), "immutable_identity": None,
            "mathematical_refusal": refuses(action),
            "decoder_claim": "No generic Node decoder rejection or runtime qualification claimed.",
        })

    for name, mutate in [
        ("primary-P-substituted-for-O", lambda item: item[14].__setitem__(0, route_id)),
        ("primary-extra-attribute", lambda item: item[9].__setitem__("uid", 24)),
        ("primary-extra-provenance", lambda item: item.__setitem__(11, bytes(32))),
        ("primary-multiple-targets", lambda item: item[14].append(object_id)),
        ("primary-wrong-entry-kind", lambda item: item.__setitem__(1, 4)),
        ("primary-wrong-pointer-width", lambda item: item[9].__setitem__("index.occurrences", bytes(31))),
        ("primary-empty-continuation", lambda item: item[9].__setitem__("index.occurrences", empty)),
    ]:
        model = deepcopy(primary)
        mutate(model[2][0][2])
        add(name, model, lambda model=model: validate_primary(data, model, parent), "primary row")

    route = data.models["parent-present-route"]
    for name, model in [
        ("route-omitted-repeated-graft", leaf([(b"left", deepcopy(route[2][0][2]))])),
        ("route-extra-source-key", leaf([(b"absent", deepcopy(route[2][0][2]))])),
        ("route-dot-component", leaf([(b"..", deepcopy(route[2][0][2]))])),
        ("route-component-256", leaf([(b"x" * 256, deepcopy(route[2][0][2]))])),
        ("route-forbidden-gap-properties", leaf([(b"left", deepcopy(route[2][0][2]))], primary[3])),
        ("route-terminal-at-graft", leaf([(b"left", row(object_id))])),
    ]:
        def assess(model=model):
            actual = route_occurrences(data, model, parent, object_id, cbor(VALUE))
            expected = [item for item in source_occurrences(data, parent) if item["value"] == cbor(VALUE)]
            if actual != expected:
                raise ValueError("route omitted matching source occurrences")
        add(name, model, assess, "present route")

    for name, model in [
        ("terminal-explicit-empty-attrs", leaf([(b"present", {1: 7, 9: {}, 14: [object_id]})])),
        ("terminal-forward-pointer-at-file", leaf([(b"present", row(object_id, empty))])),
        ("missing-route-actually-present", leaf([(b"present", row(object_id))])),
        ("terminal-wrong-O", leaf([(b"present", row(empty))])),
    ]:
        predicate = None if name == "missing-route-actually-present" else cbor(VALUE)
        add(name, model, lambda model=model, predicate=predicate: route_occurrences(
            data, model, child, object_id, predicate,
        ), "terminal source predicate")

    model = deepcopy(primary)
    del model[3]
    add("primary-omitted-gap-binding", model, lambda: validate_primary(data, model, parent), "coverage")
    model = deepcopy(primary)
    model[3] = gap_props(empty)
    add("primary-bound-empty-G", model, lambda: validate_primary(data, model, parent), "coverage")

    gap = data.models["parent-gaps"]
    model = deepcopy(gap)
    model[2][0][2][14] = [empty]
    add("gap-target-not-key-O", model, lambda: validate_primary(data, primary, parent, model), "missing objects")
    model = deepcopy(gap)
    model[2][0][2] = row(object_id)
    add("gap-terminal-instead-of-forward", model, lambda: validate_primary(data, primary, parent, model), "missing objects")
    model = leaf([(object_id, deepcopy(gap[2][0][2])), (bytes(32), row(bytes(32), empty))])
    add("gap-extra-object", model, lambda: validate_primary(data, primary, parent, model), "missing objects")

    for name, properties, placement in [
        ("gap-binding-bare", {"index-gaps": object_id.hex()}, "primary"),
        ("gap-binding-inherits", {"index-gaps": {"inherit": True, "value": object_id.hex()}}, "primary"),
        ("gap-binding-uppercase", {"index-gaps": {"inherit": False, "value": "AB" * 32}}, "primary"),
        ("gap-binding-extra-property", {**primary[3], "domain": "public"}, "primary"),
        ("gap-binding-on-namespace-owner", primary[3], "namespace owner"),
        ("gap-binding-on-route-root", primary[3], "route"),
        ("gap-binding-on-G-root", primary[3], "missing objects"),
        ("gap-binding-on-nonroot", primary[3], "nonroot"),
        ("primary-explicit-empty-properties", {}, "primary"),
    ]:
        model = leaf([], properties)
        add(name, model, lambda properties=properties, placement=placement: binding(
            properties, placement,
        ), f"property placement: {placement}")

    model = leaf([(b"local-route-key", row(object_id, empty))])
    add("local-route-reused-as-primary", model, lambda: validate_primary(data, model, parent), "role distinction")
    return results


def verify(data, owners):
    """Checks acyclicity, all finite recurrences and precise ordinary-data context."""
    outcomes = []
    all_recipe_keys = [bytes.fromhex(item["memo_lookup_key"]) for item in data.recipes]
    all_owners = [owner for _, owner, _ in owners]
    for name, owner, index in owners:
        owner_model = data.by_digest[owner]
        assert owner_model[3]["index-roots"] == {"inherit": False, "value": {ATTRIBUTE: index.hex()}}
        found = validate_primary(data, data.by_digest[index], owner)
        for item in found:
            assert item["object"] == data.object_id
        result = {
            "name": name, "owner_R": owner.hex(), "primary_I": index.hex(),
            "present_occurrences": sum(item["value"] is not None for item in found),
            "missing_occurrences": sum(item["value"] is None for item in found),
            "occurrences": [{
                "local_hops_hex": [hop.hex() for hop in item["hops"]],
                "composed_length": sum(len(hop) for hop in item["hops"]) + len(item["hops"]) - 1,
                "object_O": item["object"].hex(),
                "canonical_value_hex": None if item["value"] is None else item["value"].hex(),
                "unverified_policy_layers": list(item["layers"]),
            } for item in found],
        }
        outcomes.append(result)
    repeated = outcomes[1]
    assert repeated["present_occurrences"] == repeated["missing_occurrences"] == 2
    present = [item for item in repeated["occurrences"] if item["canonical_value_hex"] is not None]
    assert present[0]["unverified_policy_layers"] != present[1]["unverified_policy_layers"]
    assert outcomes[2]["present_occurrences"] == 0 and outcomes[2]["missing_occurrences"] == 1
    assert outcomes[3]["occurrences"][0]["composed_length"] == 4355

    # Closed carrier field tables can name only actual O, child P and G.
    # They have no slot for an owner, containing Commit, recipe or memo q.
    auxiliary = {
        bytes.fromhex(item["node_id"]) for item in data.records
        if item["role_claim"] != "ordinary namespace root"
    }
    order = {}
    for item in data.records:
        order.setdefault(bytes.fromhex(item["node_id"]), item["construction_order"])
    for record in data.records:
        if record["role_claim"] == "ordinary namespace root":
            continue
        model = data.models[record["name"]]
        edges = []
        for _, entry in expanded(model):
            pointer = closed_row(entry, data.object_id, 9 in entry)
            if pointer is not None:
                edges.append(pointer)
        if 3 in model:
            edges.append(binding(model[3], "primary"))
        identity = bytes.fromhex(record["node_id"])
        assert all(edge in auxiliary and order[edge] < order[identity] for edge in edges)
        wire = bytes.fromhex(record["wire_hex"])
        assert all(backref not in wire for backref in all_owners + all_recipe_keys)
        assert data.object_id not in auxiliary
    return outcomes
