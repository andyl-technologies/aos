/* SPDX-License-Identifier: Apache-2.0 */

#ifndef AOS_TESTS_CRUCIBLE_PHASE2_QEMU_FAULT_MANIFEST_BINDINGS_H
#define AOS_TESTS_CRUCIBLE_PHASE2_QEMU_FAULT_MANIFEST_BINDINGS_H

#include <qemu-plugin.h>
#include <stdint.h>
#include <string.h>

static void crucible_test_identity(uint8_t identity[32], uint8_t domain,
                                   uint32_t row)
{
    memset(identity, domain, 32);
    identity[0] = row;
    identity[1] = row >> 8;
    identity[2] = row >> 16;
    identity[3] = row >> 24;
    identity[31] = domain;
}

/*
 * Enables every aggregate-VMState participant exactly as a production launch
 * does. A lifecycle fingerprint and a snapshot are invalid if any realized
 * manifest remains only partially bound, so callers must treat any returned
 * message as a fatal fixture setup error.
 */
static const char *crucible_test_bind_all_fault_manifests(void)
{
    const char *cpu_model = NULL;
    uint8_t identity[32];
    uint8_t secondary[32];
    uint8_t tertiary[32];
    uint8_t quaternary[32];
    uint8_t quinary[32];
    uint8_t senary[32];
    uint8_t manifest_digest[32];
    uint16_t architecture = 0;
    size_t count;

    count = qemu_plugin_crucible_fault_register_manifest(
        NULL, 0, &architecture, &cpu_model);
    if (count == 0 || !cpu_model || !*cpu_model) {
        return "register manifest was absent";
    }
    crucible_test_identity(identity, 0x10, 0);
    if (qemu_plugin_crucible_fault_register_bind_architecture(identity) != 0) {
        return "register architecture binding was rejected";
    }
    for (size_t index = 0; index < count; index++) {
        crucible_test_identity(identity, 0x11, index + 1);
        if (qemu_plugin_crucible_fault_register_bind(
                identity, index + 1) != 0) {
            return "register row binding was rejected";
        }
    }
    if (qemu_plugin_crucible_fault_register_bindings_seal() != 0) {
        return "complete register manifest could not be sealed";
    }

    count = qemu_plugin_crucible_fault_interrupt_manifest(
        NULL, 0, &architecture);
    if (count == 0) {
        return "interrupt manifest was absent";
    }
    for (size_t index = 0; index < count; index++) {
        crucible_test_identity(identity, 0x20, index + 1);
        crucible_test_identity(secondary, 0x21, index + 1);
        crucible_test_identity(tertiary, 0x22, index + 1);
        if (qemu_plugin_crucible_fault_interrupt_bind(
                index, identity, secondary, tertiary) != 0) {
            return "interrupt row binding was rejected";
        }
    }
    if (qemu_plugin_crucible_fault_interrupt_bindings_seal() != 0) {
        return "complete interrupt manifest could not be sealed";
    }

    count = qemu_plugin_crucible_fault_hardware_error_manifest(
        NULL, 0, &architecture);
    if (count == 0) {
        return "hardware-error manifest was absent";
    }
    for (size_t index = 0; index < count; index++) {
        crucible_test_identity(identity, 0x30, index + 1);
        crucible_test_identity(secondary, 0x31, index + 1);
        crucible_test_identity(tertiary, 0x32, index + 1);
        crucible_test_identity(quaternary, 0x33, index + 1);
        crucible_test_identity(quinary, 0x34, index + 1);
        crucible_test_identity(senary, 0x35, index + 1);
        if (qemu_plugin_crucible_fault_hardware_error_bind(
                index, identity, secondary, tertiary, quaternary,
                quinary, senary) != 0) {
            return "hardware-error row binding was rejected";
        }
    }
    memset(manifest_digest, 0xa4, sizeof(manifest_digest));
    if (qemu_plugin_crucible_fault_hardware_error_bindings_seal(
            manifest_digest) != 0) {
        return "complete hardware-error manifest could not be sealed";
    }

    count = qemu_plugin_crucible_fault_clock_manifest(
        NULL, 0, &architecture);
    if (count == 0) {
        return "clock manifest was absent";
    }
    for (size_t index = 0; index < count; index++) {
        crucible_test_identity(identity, 0x40, index + 1);
        if (qemu_plugin_crucible_fault_clock_bind(index, identity) != 0) {
            return "clock row binding was rejected";
        }
    }
    memset(manifest_digest, 0xa5, sizeof(manifest_digest));
    if (qemu_plugin_crucible_fault_clock_bindings_seal(manifest_digest) != 0) {
        return "complete clock manifest could not be sealed";
    }
    return NULL;
}

#endif
