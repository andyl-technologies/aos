"""Build confined SELECT-only projections for the fresh Managed GC pair.

The Native guest executes these statements in one read-only transaction. Stable
API identities select actual numeric SQL IDs; inventory and Delete observations
must match those current rows. This module supplies no capability or mutation.
"""

import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(value):
    require(isinstance(value, str) and 0 < len(value.encode()) <= 64
            and value.strip() == value
            and not any(ord(character) < 32 or ord(character) == 127 for character in value),
            "Managed SQL stable identity differs")
    return value


def current_pins_sql(setup, coordinates):
    """Resolve exact API stable identities to current placement and binding rows."""
    run = coordinates["runId"]
    require(isinstance(run, str) and re.fullmatch(r"[0-9a-f]{32}", run),
            "Managed SQL run identity differs")
    slug = "managed-" + run + "/containers"
    prefix = "qualification/oci-terminal-cleanup/" + run
    registry, binding, placement = setup["registry"], setup["binding"], setup["placement"]
    require(registry["slug"] == slug and placement["name"] == "managed-gc"
            and placement["prefix"] == prefix and coordinates["gcPrefix"] == prefix,
            "Managed SQL selection differs from the original API placement")
    registry_id = identity(registry["stableId"]).replace("'", "''")
    binding_id = identity(binding["stableId"]).replace("'", "''")
    return f"""
        SELECT registry.id AS registry_id, registry.stable_id AS registry_stable_id,
               registry.resource_version AS registry_resource_version,
               placement.id AS placement_id, placement.prefix AS placement_prefix,
               placement.resource_version AS placement_resource_version,
               placement.write_spec_version AS placement_write_spec_version,
               observation.observation_version AS placement_observation_version,
               binding.id AS binding_id, binding.stable_id AS binding_stable_id,
               binding.resource_version AS binding_resource_version,
               writer.current_write_revision AS binding_write_revision,
               state.mutation_epoch AS captured_mutation_epoch
        FROM registries registry
        JOIN surface_placements placement ON placement.registry_id = registry.id
        JOIN surface_placement_observations observation ON observation.placement_id = placement.id
        JOIN bindings binding ON binding.id = placement.binding_id
        JOIN binding_write_state writer ON writer.binding_id = binding.id
        JOIN oci_registry_state state ON state.registry_id = registry.id
        WHERE registry.stable_id = '{registry_id}' AND registry.slug = '{slug}'
          AND placement.name = 'managed-gc' AND placement.prefix = '{prefix}'
          AND placement.kind = 'complete' AND placement.desired_state = 'active'
          AND observation.state = 'ready' AND observation.completeness = 'complete'
          AND binding.stable_id = '{binding_id}' AND binding.kind = 'deployment_r2'
        LIMIT 2
    """


def one_row_projection(query):
    """Retain every selected row up to the explicit two-row ambiguity bound."""
    return "SELECT COALESCE(json_agg(row_to_json(selected)), '[]'::json) FROM (" + query + ") selected"


def current_projection_sql(gc, setup, coordinates, pins=None):
    """Read current IDs alone, or exact current inventory and Delete capability."""
    queries = {"pins": current_pins_sql(setup, coordinates)}
    if pins is not None:
        for field in ("registry_id", "placement_id", "binding_id"):
            require(type(pins[field]) is int and pins[field] > 0, "Managed numeric SQL pin differs")
        queries["inventory"] = gc.inventory_gc.current_inventory_sql(
            pins["registry_id"], pins["placement_id"])
        queries["capability"] = gc.managed_capability_sql(pins["binding_id"])
    members = ", ".join("'" + name + "', (" + one_row_projection(query) + ")"
                        for name, query in queries.items())
    return transaction("SELECT json_build_object(" + members + ")::text", coordinates["database"])


def action_projection_sql(gc, run_id, database):
    """Read actual frozen actions with acknowledged evidence, never a guessed claim."""
    identity(run_id)
    return transaction(one_row_projection(gc.action_evidence_sql(run_id)), database)


def capability_projection_sql(gc, setup, coordinates, pins):
    """Read the independent Delete probe before beginning scoped inventory work."""
    require(type(pins["binding_id"]) is int and pins["binding_id"] > 0,
            "Managed capability SQL binding selector differs")
    return transaction("SELECT json_build_object('pins', (" + one_row_projection(
        current_pins_sql(setup, coordinates)) + "), 'capability', (" + one_row_projection(
        gc.managed_capability_sql(pins["binding_id"])) + "))::text", coordinates["database"])


def exact_managed_capability(observed, gc, original_pins):
    """Require a separately valid current credential-free Managed Delete row."""
    require(isinstance(observed, dict) and set(observed) == {"pins", "capability"},
            "Managed capability projection fields differ")
    pins = exact_current_projection({"pins": observed["pins"]}, gc, original_pins)
    require(isinstance(observed["capability"], list) and len(observed["capability"]) == 1,
            "Managed separately probed Delete capability is missing or ambiguous")
    capability = observed["capability"][0]
    require(capability["kind"] == "deployment_r2" and capability["state"] == "valid"
            and capability["delete_credential_purpose"] is None
            and capability["delete_credential_generation"] is None
            and capability["binding_id"] == pins["binding_id"]
            and capability["binding_resource_version"] == pins["binding_resource_version"]
            and capability["binding_write_revision"] == pins["binding_write_revision"]
            and capability["current_write_revision"] == pins["binding_write_revision"]
            and capability["capability_fingerprint"] and capability["resource_version"] > 0,
            "Managed selected Delete row is not the actual independent current probe")
    return pins


def transaction(statement, database):
    """Bound one PostgreSQL metadata snapshot without schema or row writes."""
    require(isinstance(statement, str) and statement.lstrip().startswith("SELECT ")
            and ";" not in statement and len(statement.encode()) <= 32 * 1024,
            "Managed SQL projection is not one bounded SELECT")
    require(isinstance(database, str) and re.fullmatch(r"fleet_managed_[0-9a-f]{32}", database),
            "Managed SQL database differs from the fresh pair")
    statement = ("SELECT json_build_object('database', current_database(), 'value', ("
                 + statement + ")::json)::text")
    return ("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
            "SET LOCAL statement_timeout = '15s'; SET LOCAL lock_timeout = '5s'; "
            + statement + "; COMMIT;")


def exact_current_projection(observed, gc, original_pins=None):
    """Require actual singleton pins and, when requested, current probed inventory."""
    require(isinstance(observed, dict) and set(observed) in ({"pins"}, {"pins", "inventory", "capability"}),
            "Managed SQL projection fields differ")
    require(isinstance(observed["pins"], list) and len(observed["pins"]) == 1,
            "Managed SQL current target is missing or ambiguous")
    pins = observed["pins"][0]
    for field in ("registry_id", "placement_id", "registry_resource_version",
                  "placement_resource_version", "placement_write_spec_version",
                  "placement_observation_version", "binding_id", "binding_resource_version",
                  "binding_write_revision"):
        require(type(pins[field]) is int and pins[field] > 0, "Managed current SQL pin is invalid")
    require(type(pins["captured_mutation_epoch"]) is int and pins["captured_mutation_epoch"] >= 0,
            "Managed current mutation epoch is invalid")
    if original_pins is not None:
        for field in ("registry_id", "registry_stable_id", "placement_id", "placement_prefix",
                      "binding_id", "binding_stable_id"):
            require(pins[field] == original_pins[field], "Managed selected SQL resource changed")
    if "inventory" in observed:
        require(len(observed["inventory"]) == len(observed["capability"]) == 1,
                "Managed current inventory or separately probed Delete capability is missing")
        gc.require_managed_inventory(observed["inventory"][0], observed["capability"][0], pins)
    return pins
