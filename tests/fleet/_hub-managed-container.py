"""Produce a genuine signed container graph for a fresh Managed fleet pair.

Commands use the selected ordinary CLI/APR packages. Private command output,
credentials and Distribution bodies remain in the fresh guest evidence root.
The helper does not install a provider, configure a route or grant permission.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import stat
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request


MAX_DOCUMENT_BYTES = 4 * 1024 * 1024


def _coordinates(coordinates):
    if not re.fullmatch(r"[a-f0-9]{32}", coordinates["runId"]):
        raise ValueError("Managed producer run identity is invalid")
    root = Path(coordinates["clientRoot"])
    if not root.is_absolute() or ".." in root.parts or str(root) == "/":
        raise ValueError("Managed producer requires a fresh absolute guest root")
    origin = urllib.parse.urlsplit(coordinates["workerOrigin"])
    if (origin.scheme != "https" or not origin.hostname or origin.username
            or origin.password or origin.path or origin.query or origin.fragment):
        raise ValueError("Managed producer requires an exact HTTPS origin")
    _registry_slug(coordinates)


def _registry_slug(coordinates):
    """Keep each ordinary publisher in its explicitly selected fresh namespace."""
    default = "managed-" + coordinates["runId"]
    organization = coordinates.get("registryOrganizationSlug", default)
    if organization not in {default, "external-" + coordinates["runId"]}:
        raise ValueError("Container publisher organization leaves its selected run")
    if organization.startswith("external-") and coordinates["workerOrigin"] != "https://localhost:4673":
        raise ValueError("External container publisher addresses another logical pair")
    return organization + "/containers"


def _guest(client, tools, coordinates, action, **values):
    _coordinates(coordinates)
    code = Path(__file__).read_text()
    selection = {"tools": tools, "coordinates": coordinates, "action": action,
        "helperSha256": hashlib.sha256(code.encode()).hexdigest(), **values}
    encoded = base64.b64encode(json.dumps(selection).encode()).decode()
    command = (f"{shlex.quote(tools['python'])} - <<'MANAGED_CONTAINER_PROGRAM'\n"
        + code + "\n_guest_main(json.loads(base64.b64decode("
        + repr(encoded) + ")))\nMANAGED_CONTAINER_PROGRAM\n")
    # The agent transport keeps tokens and raw diagnostics out of VM command logs.
    status, stdout, _ = client.agent.request(command.encode(), timeout=1200)
    if status:
        raise RuntimeError("Managed container command failed; private guest evidence retained")
    return json.loads(stdout)


def prepare_managed_container_source(client, tools, coordinates):
    """Create real signing material and finalize the selected container inputs."""
    return _guest(client, tools, coordinates, "prepare")


def publish_managed_container(client, tools, controls, coordinates, registry, source, refresh_token):
    """Stage, index a signed sidecar, then commit the actual container tag."""
    slug = registry["slug"]
    if slug != _registry_slug(coordinates):
        raise ValueError("Managed producer registry differs from its run")

    stage = _guest(client, tools, coordinates, "stage", source=source,
        registry=slug, token=refresh_token())
    signed = _guest(client, tools, coordinates, "release", source=source, registry=slug)
    upload = _guest(client, tools, coordinates, "registry-upload", source=source,
        registry=slug, token=refresh_token())

    deadline = time.monotonic() + 240
    indexes = []
    while True:
        current = controls.call("RegistryService", "GetRegistry", {"slug": slug})["registry"]
        indexes.append({"indexState": current.get("indexState"),
            "indexError": current.get("indexError"),
            "lastIndexedCommit": current.get("lastIndexedCommit")})
        if (current.get("indexState") == "fresh"
                and current.get("lastIndexedCommit") == signed["sourceCommit"]):
            break
        if time.monotonic() >= deadline:
            _guest(client, tools, coordinates, "retain-index", observations=indexes)
            raise ValueError("Managed signed sidecar did not reach its exact current index")
        time.sleep(2)

    _guest(client, tools, coordinates, "retain-index", observations=indexes)
    published = _guest(client, tools, coordinates, "publish", source=source,
        registry=slug, token=refresh_token())
    return {"stage": stage, "signedSource": signed, "registryUpload": upload,
        "indexObservations": indexes, "containerPublication": published}


def upload_managed_unrooted_blob(client, tools, coordinates, registry, refresh_token):
    """Upload one retained random 256-byte blob through normal Distribution."""
    return _guest(client, tools, coordinates, "unrooted", registry=registry["slug"],
        token=refresh_token())


def root_mutation(client, tools, coordinates, registry, source, refresh_token):
    """Put a fresh tag for the verified retained index through Distribution."""
    return _guest(client, tools, coordinates, "root-mutation", registry=registry["slug"],
        source=source, token=refresh_token())


def prepare_unrooted_root(client, tools, coordinates, registry, source, refresh_token):
    """Upload and read back one distinct untagged index with real retained children."""
    return _guest(client, tools, coordinates, "prepare-root-candidate", registry=registry["slug"],
        source=source, token=refresh_token())


def root_candidate(client, tools, coordinates, registry, candidate, refresh_token):
    """Tag the exact previously retained unrooted candidate after caller GC review."""
    return _guest(client, tools, coordinates, "root-candidate", registry=registry["slug"],
        candidate=candidate, token=refresh_token())


def _write_private(path, value):
    with path.open("x") as output:
        os.chmod(path, 0o600)
        json.dump(value, output, sort_keys=True)
        output.write("\n")


def _result_json(raw):
    return json.loads(raw)


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise ValueError("Container root digest is invalid")
    return value


def _run(root, environment, label, argv, *, json_output=False, cwd=None):
    command_root = root / label
    command_root.mkdir(mode=0o700)
    _write_private(command_root / "arguments.private.json", argv)
    with (command_root / "stdout.private").open("xb") as stdout:
        with (command_root / "stderr.private").open("xb") as stderr:
            result = subprocess.run(argv, cwd=cwd, env=environment, stdout=stdout, stderr=stderr,
                timeout=1100, check=False)
    _write_private(command_root / "terminal.json", {"exitCode": result.returncode})
    if result.returncode:
        raise RuntimeError("Selected ordinary command failed: " + label)
    if json_output:
        path = command_root / "stdout.private"
        if path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise ValueError("Command JSON exceeds its evidence bound")
        return _result_json(path.read_bytes())
    return command_root


def _environment(root, tools):
    environment = dict(os.environ)
    if not environment.get("HOME"):
        raise ValueError("Guest publisher HOME is absent")
    environment.update({"XDG_CONFIG_HOME": str(root / "publisher/.config"),
        "XDG_DATA_HOME": str(root / "publisher/.local/share"),
        "XDG_CACHE_HOME": str(root / "publisher/.cache"), "NIX_REMOTE": "",
        "NIX_CONF_DIR": str(root / "publisher/.config/nix")})
    environment["PATH"] = ":".join([str(Path(tools["git"]).parent),
        tools["opensshBin"], tools["nixBin"], environment.get("PATH", "")])
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "NIX_CONF_DIR"):
        Path(environment[key]).mkdir(mode=0o700, parents=True, exist_ok=True)
    (Path(environment["NIX_CONF_DIR"]) / "nix.conf").write_text(
        "experimental-features = nix-command\nsandbox = false\nbuild-users-group =\n")
    return environment


def _source(root, selected):
    source = json.loads((root / "source.private.json").read_bytes())
    if source != selected["source"] or source["helperSha256"] != selected["helperSha256"]:
        raise ValueError("Managed container source selection changed")
    return source


def _container_arguments(tools, coordinates, source, slug, token):
    authority = urllib.parse.urlsplit(coordinates["workerOrigin"]).netloc
    finalized = source["finalized"]
    return [tools["aos"], "--json", "--progress", "off", "--color", "never",
        "container", "publish", "aos", authority + "/aos:managed-" + coordinates["runId"],
        "--release", finalized["release"], "--release-layout", finalized["layout"],
        "--signature-input", finalized["signature_input"], "--registry", slug,
        "--registry-origin", coordinates["workerOrigin"], "--registry-token", token,
        "--hub", coordinates["workerOrigin"], "--token", token]


def _prepare_documentation(root, environment, tools, registry_root):
    """Publish and retain real option documentation before runtime selection."""
    selected = tools.get("documentedPackage")
    if selected is None:
        return None
    if (not isinstance(selected, dict) or set(selected) != {"storePath", "version"}
            or any(not isinstance(selected[field], str)
                or not selected[field].startswith("/nix/store/") for field in ("storePath",))
            or not isinstance(selected["version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", selected["version"])):
        raise ValueError("Documented package must use the selected source-built package")
    _run(root, environment, "apr-publish-documentation", [tools["apr"], "publish", selected["storePath"],
        "--registry", "containers", "--key-id", "initial"], cwd=tools["publicationProject"])
    catalog = tomllib.loads((registry_root / "packages/a/aos-hub.toml").read_text())
    matches = [entry["platforms"]["x86_64-linux"]["module_documentation"]
        for entry in catalog["versions"] if entry["version"] == selected["version"]]
    if len(matches) != 1:
        raise ValueError("Actual documented package identity is missing or ambiguous")
    identity = matches[0]
    descriptor = os.open(Path(identity["store_path"]) / "options.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not 16 <= before.st_size <= 262144:
            raise ValueError("Actual canonical documentation exceeds the cache admission bound")
        body = source.read(262145)
        after = os.fstat(source.fileno())
    if (len(body) != before.st_size or any(getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("Actual documentation changed during independent readback")
    digest = hashlib.sha256(body).hexdigest()
    document = json.loads(body)
    if (identity["document_sha256"] != "sha256:" + digest or identity["document_size"] != len(body)
            or document.get("schema") != "aos.module.documentation" or not document.get("options")):
        raise ValueError("Actual signed documentation lacks canonical option content")
    path = root / "document.private.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"file": str(path), "sha256": digest, "byteSize": len(body),
        "relativePath": "-/api/v1/documentation/sha256:" + digest, "identity": identity}


def _prepare(root, selected):
    tools = selected["tools"]
    environment = _environment(root, tools)
    key = Path(environment["XDG_CONFIG_HOME"]) / "apm/keys/containers-initial.key"
    generated = _run(root, environment, "key", [tools["apr"], "keys", "generate",
        "initial", "--registry", "containers"])
    key_output = (generated / "stdout.private").read_text() + (generated / "stderr.private").read_text()
    trust_keys = re.findall(r"Public key:\s*(containers:Ed25519:[^\s]+)", key_output)
    if len(trust_keys) != 1 or not key.is_file():
        raise ValueError("Actual APR signing material is missing or ambiguous")
    trust_key = trust_keys[0]

    # APR creates its first commit before a clone-local configuration exists.
    environment.update({"GIT_AUTHOR_NAME": "Managed Fleet Publisher",
        "GIT_AUTHOR_EMAIL": "fleet-publisher@example.test",
        "GIT_COMMITTER_NAME": "Managed Fleet Publisher",
        "GIT_COMMITTER_EMAIL": "fleet-publisher@example.test"})
    _run(root, environment, "create", [tools["apr"], "create", "containers",
        "--trust-key", trust_key, "--trust-key-id", "initial", "--key", str(key)])
    registry_root = Path(environment["XDG_DATA_HOME"]) / "apm/registries/containers"
    for field, value in (("user.name", "Managed Fleet Publisher"),
            ("user.email", "fleet-publisher@example.test")):
        _run(root, environment, "git-" + field, [tools["git"], "-C", str(registry_root),
            "config", "--local", field, value])
    config_directory = Path(environment["XDG_CONFIG_HOME"]) / "apm/registries.d"
    config_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    (config_directory / "containers.toml").write_text(
        '[registry]\nname = "containers"\nurl = ' + json.dumps("file://" + str(registry_root))
        + '\n\n[registry.signing_keys]\ninitial = ' + json.dumps(str(key)) + '\n')

    pae = root / "container.pae"
    ordinary = [tools["aos"], "--json", "--progress", "off", "--color", "never", "container"]
    _run(root, environment, "prepare-signature", ordinary + ["prepare-signature",
        tools["containerPublicationInputs"], "--output", str(pae)])
    _run(root, environment, "sign", [str(Path(tools["opensshBin"]) / "ssh-keygen"),
        "-Y", "sign", "-f", str(key), "-n", "aos-container-signature-dsse-v1", str(pae)])
    finalized = _run(root, environment, "finalize-signature", ordinary + ["finalize-signature",
        tools["containerPublicationInputs"], "--signer", trust_key, "--signature", str(pae) + ".sig",
        "--output", str(root / "finalized")], json_output=True)
    if finalized.get("verification") != "verified-external-sshsig":
        raise ValueError("Actual container signature finalization refused")
    _digest(finalized["index_digest"])
    for field in ("release", "layout", "signature_input"):
        path = Path(finalized[field])
        if not path.resolve().is_relative_to(root.resolve()) or not path.exists():
            raise ValueError("Finalized container output escaped its fresh root")
    document = _prepare_documentation(root, environment, tools, registry_root)
    commit_root = _run(root, environment, "initial-commit", [tools["git"], "-C",
        str(registry_root), "rev-parse", "HEAD"])
    commit = (commit_root / "stdout.private").read_text().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", commit):
        raise ValueError("APR registry commit is invalid")
    source = {"version": 1, "helperSha256": selected["helperSha256"], "trustKey": trust_key,
        "sourceCommit": commit, "surfaceRoot": str(root / "surface"),
        "publisherHome": str(root / "publisher"), "registryRoot": str(registry_root),
        "privateEnvironmentPath": str(root / "environment.private.json"), "finalized": finalized}
    if document is not None:
        source["document"] = document
    configured_environment = {key: value for key, value in environment.items()
        if key in {"HOME", "PATH", "NIX_REMOTE", "NIX_CONF_DIR"}
        or key.startswith("XDG_") or key.startswith("GIT_AUTHOR_")
        or key.startswith("GIT_COMMITTER_")}
    _write_private(root / "environment.private.json", configured_environment)
    _write_private(root / "source.private.json", source)
    return source


def _publish_action(root, selected, environment):
    tools, coordinates, action = selected["tools"], selected["coordinates"], selected["action"]
    source = _source(root, selected)
    slug = selected["registry"]
    if slug != _registry_slug(coordinates):
        raise ValueError("Managed publication registry changed")
    if action == "release":
        staged = json.loads((root / "stage-result.private.json").read_bytes())
        if staged.get("state") != "staged" or staged.get("tag_updated") is not False:
            raise ValueError("Signed sidecar requires the actual completed staging result")
    elif action == "registry-upload":
        json.loads((root / "signed-source.json").read_bytes())
    elif action == "publish":
        uploaded = json.loads((root / "registry-upload-result.private.json").read_bytes())
        signed = json.loads((root / "signed-source.json").read_bytes())
        indexes = json.loads((root / "index-observations.json").read_bytes())
        if (uploaded.get("state") != "ready" or not indexes
                or indexes[-1].get("indexState") != "fresh"
                or indexes[-1].get("lastIndexedCommit") != signed["sourceCommit"]):
            raise ValueError("Final container publish requires the actual signed current index")
    if action in {"stage", "publish"}:
        arguments = _container_arguments(tools, coordinates, source, slug, selected["token"])
        arguments += ["--idempotency-key", "managed-" + coordinates["runId"] + "-" + action]
        if action == "stage":
            arguments += ["--stage-only"]
        result = _run(root, environment, action, arguments, json_output=True)
        if result.get("index_digest") != source["finalized"]["index_digest"]:
            raise ValueError("Managed publication root differs from the signed graph")
        if action == "stage":
            if result.get("state") != "staged" or result.get("tag_updated") is not False:
                raise ValueError("Immutable graph staging did not return its closed staged form")
        elif (result.get("verification") != "verified"
                or result.get("verified_release_root") != result["index_digest"]
                or not result.get("publication_id") or not result.get("resource_version")):
            raise ValueError("Final container publication did not return a verified ready result")
        return result

    if action == "release":
        _run(root, environment, "apr-publish", [tools["apr"], "publish", tools["aosStorePath"],
            "--registry", "containers", "--key-id", "initial"], cwd=tools["publicationProject"])
        _run(root, environment, "apr-publish-helper", [tools["apr"], "publish", tools["helperStorePath"],
            "--registry", "containers", "--key-id", "initial"], cwd=tools["publicationProject"])
        finalized = source["finalized"]
        _run(root, environment, "apr-release", [tools["apr"], "release", finalized["release_identity"],
            "--registry", "containers", "--container-release", finalized["release"],
            "--container-signature-input", finalized["signature_input"],
            "--key-id", "initial",
            "--channel", "stable", "--init-channel",
            "--cache-url", coordinates["workerOrigin"] + "/" + slug,
            "--upload-url", "file://" + source["surfaceRoot"]])
        _run(root, environment, "apr-verify", [tools["apr"], "verify", "--registry", "containers"])
        commit_root = _run(root, environment, "signed-commit", [tools["git"], "-C",
            source["registryRoot"], "rev-parse", "HEAD"])
        commit = (commit_root / "stdout.private").read_text().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", commit) or commit == source["sourceCommit"]:
            raise ValueError("Signed container sidecar did not create a new source commit")
        result = {"sourceCommit": commit, "surfaceRoot": source["surfaceRoot"],
            "indexDigest": finalized["index_digest"]}
        _write_private(root / "signed-source.json", result)
        return result

    if action == "registry-upload":
        arguments = [tools["aos"], "--json", "--progress", "off",
            "--color", "never", "hub", "registry", "publish", "upload", slug,
            "--root", source["surfaceRoot"], "--hub", coordinates["workerOrigin"],
            "--token", selected["token"]]
        if _registry_slug(coordinates).startswith("external-"):
            policy = tools["providerPolicyFile"]
            if not isinstance(policy, str) or not policy.startswith(coordinates["clientRoot"].rsplit("/", 1)[0] + "/"):
                raise ValueError("External sidecar requires the actual selected private provider policy")
            arguments += ["--direct-provider-policy", policy,
                "--direct-upload-journal", str(root / "registry-direct-upload.sqlite")]
        result = _run(root, environment, action, arguments, json_output=True)
        publication = result["data"]
        if publication.get("state") != "ready":
            raise ValueError("Ordinary signed registry publication did not become ready")
        return publication
    raise ValueError("Managed publication action is unsupported")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def _header(headers, name):
    values = [value for key, value in headers.items() if key.lower() == name.lower()]
    if len(values) != 1:
        raise ValueError("Distribution response header is missing or ambiguous: " + name)
    return values[0]


def _same_origin_location(origin, previous, location):
    if not location:
        raise ValueError("Distribution upload omitted its actual Location")
    target = urllib.parse.urljoin(previous, location)
    observed, expected = urllib.parse.urlsplit(target), urllib.parse.urlsplit(origin)
    if (observed.scheme, observed.netloc) != (expected.scheme, expected.netloc):
        raise ValueError("Distribution Location changed the exact origin")
    if observed.username or observed.password or observed.fragment:
        raise ValueError("Distribution Location contains unsupported identity")
    return target


def _request(root, label, method, url, token, body, expected_status, headers=None):
    directory = root / label
    directory.mkdir(mode=0o700)
    _write_private(directory / "request.private.json", {"method": method, "url": url,
        "bodyBytes": len(body), "bodySha256": hashlib.sha256(body).hexdigest()})
    (directory / "request-body.private").write_bytes(body)
    request = urllib.request.Request(url, data=body, method=method,
        headers={"Authorization": "Bearer " + token, **(headers or {})})
    try:
        response = urllib.request.build_opener(_NoRedirect()).open(request, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_DOCUMENT_BYTES + 1)
        (directory / "response-body.private").write_bytes(raw)
        receipt = {"status": response.status, "headers": dict(response.headers.items()),
            "rawHeaders": list(response.headers.items()),
            "bodyBytes": len(raw), "bodySha256": hashlib.sha256(raw).hexdigest()}
        duplicate_identity = any(len(response.headers.get_all(name, [])) > 1
            for name in ("Location", "Docker-Content-Digest"))
    _write_private(directory / "response.private.json", receipt)
    if duplicate_identity or len(raw) > MAX_DOCUMENT_BYTES or receipt["status"] != expected_status:
        raise ValueError("Distribution request refused; actual response retained")
    return receipt


def _distribution(root, selected):
    origin, slug, token = selected["coordinates"]["workerOrigin"], selected["registry"], selected["token"]
    if slug != _registry_slug(selected["coordinates"]):
        raise ValueError("Distribution fixture registry differs from the fresh run")
    published = json.loads((root / "publish-result.private.json").read_bytes())
    if published.get("verification") != "verified":
        raise ValueError("Managed GC inputs require the completed container publication")
    # The configured route uses repository `aos`, matching the signed image.
    repository = origin + "/v2/aos"
    if selected["action"] == "prepare-root-candidate":
        return _prepare_root_candidate(root, selected, repository)
    if selected["action"] == "root-candidate":
        return _tag_root_candidate(root, selected, repository)
    if selected["action"] == "unrooted":
        body = os.urandom(256)
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        first_url = repository + "/blobs/uploads/?size=256"
        first = _request(root, "unrooted-post", "POST", first_url, token, b"", 202)
        location = _same_origin_location(origin, first_url, _header(first["headers"], "Location"))
        chunk = _request(root, "unrooted-patch", "PATCH", location, token, body, 202,
            {"Content-Type": "application/octet-stream", "Content-Range": "0-255"})
        location = _same_origin_location(origin, location, _header(chunk["headers"], "Location"))
        parsed = urllib.parse.urlsplit(location)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if any(key == "digest" for key, _ in query):
            raise ValueError("Distribution Location unexpectedly preselected a digest")
        complete_url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query + [("digest", digest)])))
        complete = _request(root, "unrooted-put", "PUT", complete_url, token, b"", 201)
        if _header(complete["headers"], "Docker-Content-Digest") != digest:
            raise ValueError("Distribution completion digest differs from the retained body")
        return {"digest": digest, "bytes": 256,
            "bodyPath": str(root / "unrooted-patch/request-body.private"), "completion": complete}

    source = _source(root, selected)
    digest = _digest(source["finalized"]["index_digest"])
    blob = Path(source["finalized"]["layout"]) / "blobs/sha256" / digest.split(":")[1]
    if not blob.is_file() or blob.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("Retained signed index document is missing or exceeds its bound")
    body = blob.read_bytes()
    if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
        raise ValueError("Retained signed index document changed")
    document = json.loads(body)
    media_type = document["mediaType"]
    if media_type != "application/vnd.oci.image.index.v1+json":
        raise ValueError("Retained signed root is not an OCI image index")
    tag = "gc-root-" + selected["coordinates"]["runId"]
    receipt = _request(root, "gc-root-put", "PUT", repository + "/manifests/" + tag,
        token, body, 201, {"Content-Type": media_type})
    if _header(receipt["headers"], "Docker-Content-Digest") != digest:
        raise ValueError("Tag root mutation returned a different index digest")
    return {"tag": tag, "digest": digest, "bodyBytes": len(body), "receipt": receipt}


def _prepare_root_candidate(root, selected, repository):
    source = _source(root, selected)
    original_digest = _digest(source["finalized"]["index_digest"])
    original_path = Path(source["finalized"]["layout"]) / "blobs/sha256" / original_digest.split(":")[1]
    if not original_path.is_file() or original_path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("Signed source index is absent or exceeds its bound")
    original = original_path.read_bytes()
    if "sha256:" + hashlib.sha256(original).hexdigest() != original_digest:
        raise ValueError("Signed source index changed before candidate construction")
    document = json.loads(original)
    media_type = "application/vnd.oci.image.index.v1+json"
    if (document.get("schemaVersion") != 2 or document.get("mediaType") != media_type
            or not isinstance(document.get("manifests"), list) or not document["manifests"]):
        raise ValueError("Signed source does not contain a nonempty OCI index")
    annotations = document.setdefault("annotations", {})
    key = "org.aos.fixture.gc-candidate"
    if not isinstance(annotations, dict) or key in annotations:
        raise ValueError("Signed source already contains the fixture candidate annotation")
    annotations[key] = selected["coordinates"]["runId"]
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    if len(body) > MAX_DOCUMENT_BYTES or digest == original_digest:
        raise ValueError("Candidate index is not distinct or exceeds its bound")
    body_path = root / "root-candidate-body.private"
    with body_path.open("xb") as output:
        output.write(body)

    # Digest-only admission records real edges without creating a tag root.
    url = repository + "/manifests/" + digest
    admitted = _request(root, "candidate-index-put", "PUT", url, selected["token"],
        body, 201, {"Content-Type": media_type})
    if _header(admitted["headers"], "Docker-Content-Digest") != digest:
        raise ValueError("Candidate admission returned a different digest")
    observed = _request(root, "candidate-index-get", "GET", url, selected["token"],
        b"", 200, {"Accept": media_type})
    observed_body = (root / "candidate-index-get/response-body.private").read_bytes()
    if (_header(observed["headers"], "Docker-Content-Digest") != digest
            or _header(observed["headers"], "Content-Type").split(";", 1)[0].strip() != media_type
            or observed_body != body):
        raise ValueError("Candidate readback differs from the exact admitted OCI index")
    result = {"version": 1, "helperSha256": selected["helperSha256"],
        "registrySlug": selected["registry"], "runId": selected["coordinates"]["runId"],
        "sourceIndexDigest": original_digest, "digest": digest, "bytes": len(body),
        "mediaType": media_type, "bodyPath": str(body_path),
        "admission": admitted, "readback": observed}
    _write_private(root / "root-candidate.private.json", result)
    return result


def _tag_root_candidate(root, selected, repository):
    candidate = json.loads((root / "root-candidate.private.json").read_bytes())
    if (candidate != selected["candidate"] or candidate["helperSha256"] != selected["helperSha256"]
            or candidate["registrySlug"] != selected["registry"]
            or candidate["runId"] != selected["coordinates"]["runId"]):
        raise ValueError("Retained unrooted candidate selection changed")
    body_path = root / "root-candidate-body.private"
    if candidate["bodyPath"] != str(body_path) or body_path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("Retained candidate body path or bound changed")
    body = body_path.read_bytes()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    if len(body) != candidate["bytes"] or digest != _digest(candidate["digest"]):
        raise ValueError("Retained candidate body changed after its admission")
    tag = "gc-candidate-" + selected["coordinates"]["runId"]
    receipt = _request(root, "candidate-tag-put", "PUT", repository + "/manifests/" + tag,
        selected["token"], body, 201, {"Content-Type": candidate["mediaType"]})
    if _header(receipt["headers"], "Docker-Content-Digest") != digest:
        raise ValueError("Candidate tag mutation returned a different digest")
    return {"tag": tag, "digest": digest, "bodyBytes": len(body), "receipt": receipt}


def _guest_main(selected):
    coordinates = selected["coordinates"]
    _coordinates(coordinates)
    os.umask(0o077)
    root = Path(coordinates["clientRoot"])
    if selected["action"] == "prepare":
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
    if (root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.getuid()
            or root.stat().st_mode & 0o077):
        raise ValueError("Managed evidence root is not owner-private")
    if selected["action"] == "prepare":
        result = _prepare(root, selected)
    elif selected["action"] == "retain-index":
        _write_private(root / "index-observations.json", selected["observations"])
        result = {"path": str(root / "index-observations.json")}
    elif selected["action"] in {"unrooted", "root-mutation", "prepare-root-candidate", "root-candidate"}:
        result = _distribution(root, selected)
    else:
        environment = dict(os.environ)
        environment.update(json.loads((root / "environment.private.json").read_bytes()))
        result = _publish_action(root, selected, environment)
    _write_private(root / (selected["action"] + "-result.private.json"), result)
    print(json.dumps(result))
