/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef AOS_TESTS_CRUCIBLE_QEMU_FAULT_EVENT_ENVELOPE_H
#define AOS_TESTS_CRUCIBLE_QEMU_FAULT_EVENT_ENVELOPE_H

#define CRUCIBLE_TEST_EVENT_ENVELOPE_HEADER_BYTES 192
#define CRUCIBLE_TEST_EVENT_ENVELOPE_BUFFER_BYTES 8192

static inline uint16_t crucible_test_event_u16(const uint8_t *bytes)
{
    return bytes[0] | (uint16_t)bytes[1] << 8;
}

static inline uint32_t crucible_test_event_u32(const uint8_t *bytes)
{
    return bytes[0] | (uint32_t)bytes[1] << 8 |
           (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static inline uint64_t crucible_test_event_u64(const uint8_t *bytes)
{
    return crucible_test_event_u32(bytes) |
           (uint64_t)crucible_test_event_u32(bytes + 4) << 32;
}

static inline bool crucible_test_event_sha256_matches(
    const uint8_t *bytes, size_t length, const uint8_t expected[32])
{
    g_autoptr(GChecksum) checksum = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t actual[32];
    gsize actual_length = sizeof(actual);

    if (!checksum) {
        return false;
    }
    g_checksum_update(checksum, bytes, length);
    g_checksum_get_digest(checksum, actual, &actual_length);
    return actual_length == sizeof(actual) &&
           memcmp(actual, expected, sizeof(actual)) == 0;
}

/*
 * Returns the authenticated inner evidence from QEMU's mandatory v1 event
 * envelope. The live tests reject the envelope unless its request, evidence,
 * and public event identities agree byte-for-byte.
 */
static inline const uint8_t *crucible_test_event_evidence(
    const struct qemu_plugin_crucible_fault_event *event,
    const uint8_t *envelope, size_t envelope_length,
    size_t *evidence_length)
{
    uint32_t request_length;
    uint32_t encoded_evidence_length;
    const uint8_t *request;
    const uint8_t *evidence;

    if (!event || !envelope || !evidence_length ||
        qemu_plugin_crucible_fault_event_envelope_version() != 1 ||
        envelope_length < CRUCIBLE_TEST_EVENT_ENVELOPE_HEADER_BYTES ||
        memcmp(envelope, "CRUCEVQ1", 8) != 0 ||
        crucible_test_event_u16(envelope + 8) != 1 ||
        crucible_test_event_u16(envelope + 10) != 0 ||
        crucible_test_event_u32(envelope + 20) != 0) {
        return NULL;
    }

    request_length = crucible_test_event_u32(envelope + 12);
    encoded_evidence_length = crucible_test_event_u32(envelope + 16);
    if (request_length < CRUCIBLE_NODE_FAULT_PAYLOAD_HEADER_V1_BYTES ||
        request_length >
            envelope_length - CRUCIBLE_TEST_EVENT_ENVELOPE_HEADER_BYTES ||
        encoded_evidence_length == 0 ||
        encoded_evidence_length != event->evidence_length ||
        encoded_evidence_length !=
            envelope_length - CRUCIBLE_TEST_EVENT_ENVELOPE_HEADER_BYTES -
                request_length) {
        return NULL;
    }

    request = envelope + CRUCIBLE_TEST_EVENT_ENVELOPE_HEADER_BYTES;
    evidence = request + request_length;
    if (!crucible_test_event_sha256_matches(
            request, request_length, envelope + 24) ||
        !crucible_test_event_sha256_matches(
            evidence, encoded_evidence_length, envelope + 56) ||
        memcmp(envelope + 88, event->binding_hash, 32) != 0 ||
        crucible_test_event_u64(envelope + 120) !=
            event->rule_command_sequence ||
        memcmp(request, "CRUCNOD1", 8) != 0 ||
        crucible_test_event_u16(
            request + CRUCIBLE_NODE_FAULT_PAYLOAD_COMMAND_KIND_OFFSET) !=
            event->command_kind ||
        crucible_test_event_u16(
            request + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_KIND_OFFSET) !=
            event->target_kind ||
        crucible_test_event_u16(
            request + CRUCIBLE_NODE_FAULT_PAYLOAD_MODEL_PHASE_OFFSET) !=
            event->model_phase ||
        crucible_test_event_u64(
            request + CRUCIBLE_NODE_FAULT_PAYLOAD_GENERATION_OFFSET) !=
            event->generation ||
        memcmp(request + CRUCIBLE_NODE_FAULT_PAYLOAD_ACTION_HASH_OFFSET,
               event->action_hash, 32) != 0 ||
        memcmp(request + CRUCIBLE_NODE_FAULT_PAYLOAD_TARGET_HASH_OFFSET,
               event->target_hash, 32) != 0) {
        return NULL;
    }
    if (event->command_kind ==
            CRUCIBLE_FAULT_COMMAND_ACCELERATOR_RESULT_TRANSFORM &&
        memcmp(envelope + 160, event->opportunity_hash, 32) != 0) {
        return NULL;
    }

    *evidence_length = encoded_evidence_length;
    return evidence;
}

#endif
