# SPDX-License-Identifier: MIT
"""Preflights the complete selected native archive before copying any leaf."""

import os
from pathlib import Path


MAX_ARCHIVE_FILES = 4096
MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_MANIFEST_BYTES = 2 * 1024**2


def preflight_archive(image, primary, saved, resources):
    """Bounds one primary image, its exact flat saved roster and resource tree."""
    descriptor, primary_metadata = image.checked_file(primary)
    os.close(descriptor)
    _, saved_files, saved_bytes = image.census(saved)
    _, resource_files, resource_bytes = image.census(resources)
    if any(path.parent != saved for path, _ in saved_files):
        raise ValueError('native saved-file archive contains a nested leaf')
    files = 1 + len(saved_files) + len(resource_files)
    total = primary_metadata.st_size + saved_bytes + resource_bytes
    if files > MAX_ARCHIVE_FILES or total > MAX_ARCHIVE_BYTES:
        raise ValueError('complete native archive credit exhausted before copying')
    return primary_metadata


def saved_manifest(image, source_root, imported_root):
    """Measures a bounded complete private saved roster before manifest creation."""
    _, files, _ = image.census(imported_root)
    if any(path.parent != imported_root for path, _ in files):
        raise ValueError('native saved-file manifest contains a nested leaf')
    for root in (source_root, imported_root):
        value = str(root)
        if (not root.is_absolute() or os.path.normpath(value) != value
                or any(character in value for character in ('\t', '\n', '\r'))):
            raise ValueError('native saved-file manifest has an ambiguous root')
    rows = ['crucible-saved-files-v1', str(source_root), str(imported_root)]
    body_bytes = sum(len(row.encode()) + 1 for row in rows)
    if body_bytes > MAX_MANIFEST_BYTES:
        raise ValueError('native saved-file manifest prefix credit exhausted')
    for path, metadata in sorted(files, key=lambda item: item[0].name):
        name = path.name
        if any(character in name for character in ('\t', '\n', '\r')):
            raise ValueError('native saved-file manifest has an ambiguous basename')
        # The exact row extent is known before hashing or allocating its body.
        row_bytes = 64 + 1 + len(str(metadata.st_size)) + 1 + len(name.encode()) + 1
        if body_bytes + row_bytes > MAX_MANIFEST_BYTES:
            raise ValueError('native saved-file manifest credit exhausted before hashing')
        rows.append(f'{image.digest(path)}\t{metadata.st_size}\t{name}')
        body_bytes += row_bytes
    return ('\n'.join(rows) + '\n').encode()


def future_path_mapping(source_root, incarnation_root):
    """Binds inert original paths to one disjoint fresh private resource root.

    The original root may have been deleted. This function never reads it;
    native custody independently checks the current destination before overwrite.
    """
    values = (str(source_root), str(incarnation_root))
    for root, value in zip((source_root, incarnation_root), values):
        if (not root.is_absolute() or os.path.normpath(value) != value
                or any(character in value for character in (':', '\t', '\n', '\r', '\0'))
                or len(value.encode()) >= 4096):
            raise ValueError('future-path mapping has an ambiguous or oversized root')
    if (source_root == incarnation_root or source_root in incarnation_root.parents
            or incarnation_root in source_root.parents):
        raise ValueError('future-path mapping roots are not disjoint')
    mapping = ':'.join(values)
    if len(mapping.encode()) >= 8192:
        raise ValueError('future-path mapping exceeds native custody credit')
    return mapping
