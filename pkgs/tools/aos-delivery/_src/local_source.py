"""Observes an exact registered Git checkout for local bundle construction.

The closed proof records local source bytes, not CI identity or deployment
authority. All inputs and outputs must remain outside the clean checkout.
"""

import hashlib
import os
import re
import subprocess

from transport import DeliveryError


REGISTERED_REFS = (
    "refs/heads/master",
    "refs/heads/dplecki/hub-hybrid-topology",
)


def git_environment():
    """Excludes ambient repository, replacement and global configuration state."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return environment


def git_output(*arguments):
    """Reads the current repository without ambient Git repository overrides."""
    try:
        return subprocess.check_output(
            ["git", "--no-replace-objects", "-c", "core.fsmonitor=false", *arguments],
            env=git_environment(),
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError:
        raise DeliveryError("local source Git inspection failed") from None


def archive_digest(revision, *paths):
    """Hashes the actual committed Git archive, including its tree metadata."""
    with subprocess.Popen(
        ["git", "--no-replace-objects", "archive", "--format=tar", revision, *paths],
        env=git_environment(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd=os.fsdecode(git_output("rev-parse", "--show-toplevel")).strip(),
    ) as process:
        value = hashlib.sha256()
        for block in iter(lambda: process.stdout.read(1 << 20), b""):
            value.update(block)
        if process.wait() != 0:
            raise DeliveryError("local source archive hashing failed")
    return "sha256:" + value.hexdigest()


def observe(revision, repository):
    """Requires the exact clean registered checkout and returns its local proof."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise DeliveryError("source revision must be a full Git SHA")

    if git_output("rev-parse", "HEAD").decode().strip() != revision:
        raise DeliveryError("local source HEAD differs from the requested revision")
    source_ref = git_output("symbolic-ref", "HEAD").decode().strip()
    if source_ref not in REGISTERED_REFS:
        raise DeliveryError("local source is outside the registered source ref")
    if git_output("rev-parse", "--verify", source_ref).decode().strip() != revision:
        raise DeliveryError("local source ref differs from the requested revision")

    urls = git_output("config", "--get-all", "remote.origin.url").decode().splitlines()
    admitted = {
        "https://github.com/" + repository,
        "https://github.com/" + repository + ".git",
        "git@github.com:" + repository + ".git",
    }
    if len(urls) != 1 or urls[0] not in admitted:
        raise DeliveryError("local source origin differs from the registered repository")

    # Ignored outputs also contaminate a local build checkout. Hidden index
    # flags must not suppress tracked changes from the cleanliness check.
    flags = git_output("ls-files", "--full-name", "-v", "-z", "--", ":/").split(b"\0")
    if any(row and (row[:1].islower() or row[:1] == b"S") for row in flags):
        raise DeliveryError("local source index hides tracked worktree changes")
    if git_output("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--", ":/"):
        raise DeliveryError("local source checkout, index and untracked files must be clean")

    tree = git_output("rev-parse", revision + "^{tree}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise DeliveryError("local source tree identity is invalid")
    return {
        "apiVersion": "https://aos.dev/attestations/local-source/v1",
        "mode": "local",
        "scope": "local bundle construction only",
        "repository": repository,
        "origin": urls[0],
        "sourceRef": source_ref,
        "revision": revision,
        "tree": tree,
        "archiveDigest": archive_digest(revision),
    }


def prove(revision, repository):
    """Rechecks identity and cleanliness after reading the committed archive."""
    proof = observe(revision, repository)
    if observe(revision, repository) != proof:
        raise DeliveryError("local source changed during proof construction")
    return proof


def recheck(proof):
    """Refuses source changes before an exclusive bundle output is created."""
    if prove(proof["revision"], proof["repository"]) != proof:
        raise DeliveryError("local source proof changed during bundle construction")
