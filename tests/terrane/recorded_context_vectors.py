"""Reproduces ordinary recorded-property trust contexts and complete recipes.

Primitive canonical CBOR is assembled from literal field tables. Decoded view,
root, vocabulary and evidence claims do not establish registration, association
or authority. Only complete positive recipes have registered memo lookup keys.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import textwrap

from pack_vectors import digest


HEADING = "## Recorded property trust context field witnesses"
LEGACY_NAMES = (
    "acl baseline chunk classify compaction_threshold compression dedup degraded "
    "domain durability encryption gap_merge_bytes hashes home index merge "
    "on-release passthrough prefetch quota reassembly redundancy reflog_retain "
    "replicate retain span_max_bytes store strict-attrs trust warm "
    "whole_pack_threshold wipe writers"
).split()


class Raw:
    """Retains preassembled primitive bytes to bypass schema encoders."""

    def __init__(self, wire):
        self.wire = wire


def head(major, argument):
    """Assembles the shortest unsigned CBOR header without a Terrane codec."""
    if argument < 24:
        return bytes([(major << 5) | argument])
    for width, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if argument < 1 << (8 * width):
            return bytes([(major << 5) | additional]) + argument.to_bytes(width, "big")
    raise ValueError("CBOR argument exceeds uint64")


def encode(value):
    """Assembles canonical CBOR with encoded-byte lexicographic map order."""
    if isinstance(value, Raw):
        return value.wire
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        fields = sorted((encode(key), encode(item)) for key, item in value.items())
        return head(5, len(fields)) + b"".join(key + item for key, item in fields)
    raise TypeError(f"unsupported primitive {type(value)}")


def diagnostic(value):
    """Displays every field without decoding emitted bytes."""
    if isinstance(value, bytes):
        return "h'" + value.hex() + "'"
    if isinstance(value, list):
        return "[" + ", ".join(map(diagnostic, value)) + "]"
    if isinstance(value, dict):
        fields = sorted(value.items(), key=lambda pair: encode(pair[0]))
        return "{" + ", ".join(diagnostic(key) + ": " + diagnostic(item)
                               for key, item in fields) + "}"
    return json.dumps(value, ensure_ascii=False)


def opaque(number):
    """Creates a fixed opaque digest field, without asserting its evidence."""
    return bytes([number]) * 32


def vocabulary(revision):
    """Constructs each fixed revision from independently transcribed names."""
    names = LEGACY_NAMES + (["index-roots"] if revision >= 2 else [])
    names += ["index-gaps"] if revision >= 3 else []
    return sorted(names, key=lambda name: name.encode("utf-8"))


def selected_rows(view=1, domain="public"):
    """Constructs a complete selected row and every nested side-evidence field."""
    return [[
        [opaque(view), opaque(4), b"dir/item"], "hash.sha256", domain, b"graft/dir/item",
        [opaque(11), opaque(12), "hash.sha256", "sha256", "1", encode(b"v" * 32),
         opaque(13), [opaque(14), opaque(15), b"source/item"],
         ["private:producer", b"mount/source/item"]],
    ]]


def base_context(revision=1):
    """Constructs the exact complete v3 ordinary field model."""
    return [3, opaque(1), "public", encode(["preset", "any"]), None, 262144,
            None, [opaque(3), revision, vocabulary(revision), []]]


def context_models():
    """Transcribes positive tuples, preserving legacy absence/presence bytes."""
    models = {
        "recorded-context-legacy-one": [1, opaque(1), "public", encode(["preset", "any"]),
                                        None, 262144],
        "recorded-context-legacy-two": [2, opaque(1), "public", encode(["preset", "any"]),
                                        None, 262144, encode(selected_rows())],
    }
    for revision in [1, 2, 3]:
        models[f"recorded-context-revision-{revision}"] = base_context(revision)
        fields = base_context(revision)
        fields[6] = encode(selected_rows())
        models[f"recorded-context-selected-{revision}"] = fields
    for name, path, value in [
        ("view", [1], opaque(2)), ("root", [7, 0], opaque(4)),
        ("domain", [2], "tenant:tenant-a"),
        ("selector", [3], encode(["all", [["preset", "strict"], ["kind", "human"]]])),
        ("baseline-empty", [4], ""), ("baseline", [4], "baseline-a"),
        ("minimum", [5], 4194304),
        ("later", [7, 3], ["index-gaps", "index-roots"]),
        ("later-order", [7, 3], ["aa", "z", "é"]),
        ("later-name-limit", [7, 3], ["é" * 127 + "a"]),
    ]:
        fields = base_context()
        set_field(fields, path, value)
        models[f"recorded-context-{name}"] = fields
    fields = base_context()
    fields[7][3] = ["a"] + [f"n{number:03d}" + "x" * 251 for number in range(257)]
    models["recorded-context-later-total-limit"] = fields
    fields = base_context(2)
    fields[7][3] = ["index-gaps"]
    models["recorded-context-revision-two-later"] = fields
    fields = base_context()
    rows = selected_rows()
    second = deepcopy(rows[0])
    second[0][2] = b"dir/other"
    second[3] = b"graft/dir/other"
    second[4][5] = encode({1: [False, True, None, 24], 2: "retained"})
    fields[6] = encode(rows + [second])
    models["recorded-context-selected-multiple"] = fields
    return models


def set_field(fields, path, value):
    """Changes an explicitly listed field without an owning-format encoder."""
    for index in path[:-1]:
        fields = fields[index]
    fields[path[-1]] = value


def recipe_models(contexts):
    """Builds complete registered merge maps and optional fold data."""
    models = {}
    incoming = base_context(3)
    incoming[1] = opaque(2)
    incoming[2] = "group:incoming"
    incoming[7][0] = opaque(4)
    for name, context in contexts.items():
        # The large boundary tuple needs one owning context witness, not a
        # duplicated recipe corpus. All isolated semantic changes get recipe keys.
        if name.endswith("later-total-limit"):
            continue
        configuration = [[encode(context), encode(incoming)], None]
        models[name.replace("recorded-context", "recorded-recipe", 1)] = {
            1: "merge", 2: [opaque(5), opaque(3), opaque(4)],
            3: {"trust": {1: ["preset", "any"], 2: "terrane-verified-path/v1",
                          3: configuration, 4: []},
                "policy": ["prefer-trusted", "prefer-newer", "keep-conflict"]},
        }
    for name, preprocessing in [
        ("fold", [opaque(5), opaque(4), opaque(6), [b"a", b"a/child", b"z"]]),
        ("fold-domain", [opaque(5), opaque(4), opaque(6), [b"a", b"a/child", b"z"],
                         "group:incoming"]),
    ]:
        fields = deepcopy(models["recorded-recipe-revision-1"])
        fields[2][2] = opaque(6)
        fields[3]["trust"][3][1] = preprocessing
        models[f"recorded-recipe-{name}"] = fields
    return models


def negative_models():
    """Assembles all raw malformed tuples independently of rejecting encoders."""
    models = {}
    changes = [
        ("version-zero", [0], 0), ("version-four", [0], 4),
        ("view-short", [1], b"v" * 31), ("view-long", [1], b"v" * 33),
        ("view-type", [1], 1), ("domain-type", [2], b"public"),
        ("selector-type", [3], None), ("selector-unknown", [3], encode(["unknown", "x"])),
        ("selector-trailing", [3], encode(["preset", "any"]) + b"\x00"),
        ("baseline-type", [4], 0), ("minimum-type", [5], "262144"),
        ("selected-type", [6], []), ("selected-empty-bytes", [6], b""),
        ("selected-empty-rows", [6], encode([])), ("recorded-null", [7], None),
        ("selected-huge-bytes", [6], Raw(head(2, 2**64 - 1))),
        ("recorded-short", [7], [opaque(3), 1, vocabulary(1)]),
        ("recorded-long", [7], [opaque(3), 1, vocabulary(1), [], None]),
        ("root-short", [7, 0], b"r" * 31), ("root-long", [7, 0], b"r" * 33),
        ("root-type", [7, 0], "root"), ("revision-zero", [7, 1], 0),
        ("revision-four", [7, 1], 4), ("revision-type", [7, 1], "1"),
        ("behavior-empty", [7, 2], []), ("behavior-missing", [7, 2], vocabulary(1)[1:]),
        ("behavior-extra", [7, 2], vocabulary(2)),
        ("behavior-duplicate", [7, 2], ["acl"] + vocabulary(1)),
        ("behavior-reversed", [7, 2], list(reversed(vocabulary(1)))),
        ("behavior-type", [7, 2], None),
        ("later-empty-name", [7, 3], [""]), ("later-name-over", [7, 3], ["x" * 256]),
        ("later-unicode-over", [7, 3], ["é" * 128]),
        ("later-duplicate", [7, 3], ["future", "future"]),
        ("later-reversed", [7, 3], ["z", "aa"]),
        ("later-overlap", [7, 3], ["acl"]), ("later-type", [7, 3], [1]),
        ("later-total-over", [7, 3], ["a"] + [f"n{number:03d}" + "x" * 251
                                                    for number in range(257)] + ["zz"]),
        ("later-invalid-utf8", [7, 3], [Raw(b"\x61\xff")]),
        ("later-huge-count", [7, 3], Raw(head(4, 2**64 - 1))),
        ("behavior-huge-count", [7, 2], Raw(head(4, 2**64 - 1))),
        ("recorded-huge-count", [7], Raw(head(4, 2**64 - 1))),
        ("view-huge-bytes", [1], Raw(head(2, 2**64 - 1))),
        ("later-huge-name", [7, 3], [Raw(head(3, 2**64 - 1))]),
        ("version-nonminimal", [0], Raw(b"\x18\x03")),
        ("revision-nonminimal", [7, 1], Raw(b"\x18\x01")),
    ]
    for name, path, value in changes:
        fields = base_context()
        set_field(fields, path, value)
        models[f"recorded-negative-{name}"] = encode(fields)
    base = encode(base_context())
    for name, wire in [
        ("tuple-short", encode(base_context()[:-1])),
        ("tuple-long", encode(base_context() + [None])),
        ("tuple-type", encode({1: base_context()})),
        ("tuple-huge-count", head(4, 2**64 - 1)),
        ("tuple-nonminimal", b"\x98\x08" + base[1:]),
        ("truncated", base[:-1]), ("trailing", base + b"\x00"),
    ]:
        models[f"recorded-negative-{name}"] = wire
    row_changes = [
        ("row-view", [0, 0], opaque(2)), ("row-domain", [2], "private:other"),
        ("row-name", [1], "hash.sha512"), ("row-short-view", [0, 0], b"v" * 31),
        ("row-empty-path", [0, 2], b""), ("row-invalid-path", [3], b"../item"),
        ("row-long-component", [3], b"x" * 256),
        ("side-short-record", [4, 0], b"r" * 31),
        ("side-empty-name", [4, 2], ""),
        ("side-value-trailing", [4, 5], encode(1) + b"\x00"),
        ("side-value-nonminimal", [4, 5], b"\x18\x01"),
        ("side-empty-producer-path", [4, 8, 1], b""),
    ]
    for name, path, value in row_changes:
        rows = selected_rows()
        set_field(rows[0], path, value)
        fields = base_context()
        fields[6] = encode(rows)
        models[f"recorded-negative-{name}"] = encode(fields)
    for name, rows in [("row-duplicate", selected_rows() * 2),
                       ("row-short", [selected_rows()[0][:-1]]),
                       ("row-long", [selected_rows()[0] + [None]])]:
        fields = base_context()
        fields[6] = encode(rows)
        models[f"recorded-negative-{name}"] = encode(fields)
    rows = selected_rows()
    earlier = deepcopy(rows[0])
    earlier[0][2] = b"dir/earlier"
    earlier[3] = b"graft/dir/earlier"
    fields = base_context()
    fields[6] = encode(rows + [earlier])
    models["recorded-negative-row-reversed"] = encode(fields)
    fields = base_context()
    fields[6] = encode(selected_rows()) + b"\x00"
    models["recorded-negative-selected-trailing"] = encode(fields)
    return models


def render(binary):
    """Renders bounded named fields; only complete recipes receive memo keys."""
    contexts = context_models()
    recipes = recipe_models(contexts)
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2/TEST-3 witnesses reproduce D-107's ordinary "
        "recorded-property trust tuples and complete enclosing merge recipe "
        "fields for ALG-38, PROP-4/PROP-30, PROV-14/PROV-16 and DRV-21/DRV-22. "
        "All view/root, vocabulary and selected evidence fields are unverified "
        "claims. Syntax neither registers later names nor establishes view-root "
        "association, prefix interpretation, evaluator binding, fold execution "
        "or authority. Context tuples and configuration have no content identity. "
        "Only complete positive recipes have registered terrane-memo-v1 lookup "
        "preimages and keys; these do not assert evaluated results or admission. "
        "Every negative requires structural context-decoder refusal and receives "
        "no identity. Existing version-one/two sentinels retain their fields.", 78), ""]
    for group, models in [("context", contexts), ("recipe", recipes)]:
        for name, fields in models.items():
            wire = encode(fields)
            parts += [f"### {name}", "", "```text", diagnostic(fields), "```", "",
                      "```text", f"kind = {group}", f"wire = {wire.hex()}"]
            if group == "recipe":
                preimage = b"terrane-memo-v1\0" + wire
                parts += [f"preimage = {preimage.hex()}",
                          f"memo = {digest(binary, 'terrane-memo-v1', wire).hex()}"]
            parts += ["```", ""]
    parts += ["Selected evidence field model (embedded unchanged where present):", "",
              "```text", diagnostic(selected_rows()), "```", ""]
    for name, wire in negative_models().items():
        parts += [f"### {name}", "", "```text", "kind = context-negative",
                  f"wire = {wire.hex()}", "result = structural rejection", "```", ""]
    return ("\n".join(parts).rstrip() + "\n").encode("utf-8")


def check(reference, expected):
    """Requires exact bounded section bytes and at most one framing newline."""
    data = Path(reference).read_bytes()
    data.decode("utf-8")
    lines = data.splitlines(keepends=True)
    heading = HEADING.encode("ascii") + b"\n"
    starts = [index for index, line in enumerate(lines) if line == heading]
    if len(starts) != 1:
        raise ValueError("exact unique recorded-context section heading required")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines))
                if lines[index].startswith(b"## ")), len(lines))
    if end < len(lines) and lines[end - 1] == b"\n":
        end -= 1
    if b"".join(lines[start:end]) != expected:
        raise ValueError("recorded-context reference differs byte-for-byte")


def self_check(binary):
    """Checks literal vocabulary, complete inventory and comparator controls."""
    contexts = context_models()
    recipes = recipe_models(contexts)
    negatives = negative_models()
    names = list(contexts) + list(recipes) + list(negatives)
    if len(set(names)) != len(names) or len(LEGACY_NAMES) != 33:
        raise ValueError("ambiguous field names or incorrect literal vocabulary")
    if (len(contexts), len(recipes), len(negatives)) != (21, 22, 70):
        raise ValueError("unexpected recorded-context witness inventory")
    if [len(vocabulary(revision)) for revision in [1, 2, 3]] != [33, 34, 35]:
        raise ValueError("incorrect fixed vocabularies")
    if encode({24: None, b"": True}) != bytes.fromhex("a21818f640f5"):
        raise ValueError("map ordering is not encoded-byte lexicographic")
    if sum(len(name.encode()) for name in contexts["recorded-context-later-total-limit"][7][3]) != 65536:
        raise ValueError("incorrect preservation vocabulary boundary")
    revision_keys = [digest(binary, "terrane-memo-v1", encode(recipes[f"recorded-recipe-revision-{revision}"]))
                     for revision in [1, 2, 3]]
    if len(set(revision_keys)) != 3:
        raise ValueError("recorded revisions did not change recipe keys")
    expected = render(binary)
    with tempfile.TemporaryDirectory() as directory:
        reference = Path(directory) / "reference.md"
        for data in [expected, b"## Earlier\n\n" + expected + b"## Later\n",
                     expected + b"\n## Later\n"]:
            reference.write_bytes(data)
            check(reference, expected)
        for data in [b"", expected + expected, expected[:-1], expected + b"\n", expected + b" ",
                     expected + b"junk", expected.replace(b"\n", b"\r\n"),
                     expected + b"\n\n## Later\n", expected + b" \n## Later\n",
                     expected.replace(b"wire = ", b"wire= ", 1),
                     expected.replace(b"memo = ", b"memo = 0", 1),
                     expected.replace(b"wire = ", b"## Split\nwire = ", 1),
                     expected.replace(HEADING.encode(), b"## Recorded property\n trust context field witnesses")]:
            reference.write_bytes(data)
            try:
                check(reference, expected)
            except (ValueError, UnicodeDecodeError):
                continue
            raise ValueError("comparator accepted damaged or ambiguous section")
    return len(contexts), len(recipes), len(negatives)


def main():
    """Runs independent reproduction with an explicitly supplied raw helper."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-check", action="store_true")
    modes.add_argument("--emit", action="store_true")
    modes.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    if arguments.self_check:
        contexts, recipes, negatives = self_check(arguments.blake3_bin)
        print(f"PASS: {contexts} contexts, {recipes} complete recipes and {negatives} structural negatives")
    elif arguments.emit:
        import sys
        sys.stdout.buffer.write(render(arguments.blake3_bin))
    else:
        check(arguments.check, render(arguments.blake3_bin))
        print("PASS: exact recorded-context reference section")


if __name__ == "__main__":
    main()
