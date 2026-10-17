/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (C) 2026 Andyl, Inc.
 * Borrowed complete native map capsule reader; grants no execution authority.
 */
#include "crucible_map_source_capsule_reader.h"

#include <cstdio>

namespace {
namespace capsule = dmtcp_crucible::map_source_capsule;
unsigned char body[capsule::MaximumBytes + 1];
capsule::Candidate candidate;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *input = std::fopen(argv[1], "rb");
    if (input == nullptr) return 3;
    const auto bytes = std::fread(body, 1, sizeof(body), input);
    const bool failed = std::ferror(input) != 0;
    if (std::fclose(input) != 0 || failed || bytes > capsule::MaximumBytes) return 4;
    if (!capsule::decode_preservation(body, bytes, candidate)) return 5;
    std::puts("actual original complete map capsule readback PASS; no native authority");
    return 0;
}
