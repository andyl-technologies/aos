/* SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <spice/vd_agent.h>
#include <spice/qxl_dev.h>
#include <spice/protocol.h>
#include <spice/stream-device.h>

/* The packed public message keeps its wire prefix and row layout when its
 * variable-length monitor tail uses the standard flexible array spelling.
 */
_Static_assert(sizeof(VDAgentMonitorsConfig) == 8, "monitor prefix size");
_Static_assert(offsetof(VDAgentMonitorsConfig, monitors) == 8,
               "monitor tail offset");
_Static_assert(sizeof(VDAgentMonConfig) == 20, "monitor row size");

#define CHECK_PREFIX(type, member, bytes) \
    _Static_assert(sizeof(type) == (bytes), #type " prefix size"); \
    _Static_assert(offsetof(type, member) == (bytes), #type " tail offset")

CHECK_PREFIX(VDAgentMessage, data, 20);
CHECK_PREFIX(VDAgentFileXferStatusMessage, data, 8);
CHECK_PREFIX(VDAgentFileXferStartMessage, data, 4);
CHECK_PREFIX(VDAgentFileXferDataMessage, data, 12);
CHECK_PREFIX(VDAgentClipboard, data, 4);
CHECK_PREFIX(VDAgentAudioVolumeSync, volume, 3);
CHECK_PREFIX(VDAgentAnnounceCapabilities, caps, 4);
CHECK_PREFIX(QXLModes, modes, 4);
CHECK_PREFIX(QXLDataChunk, data, 20);
CHECK_PREFIX(QXLMessage, data, 8);
CHECK_PREFIX(QXLRasterGlyph, data, 20);
CHECK_PREFIX(QXLPathSeg, points, 8);
CHECK_PREFIX(QXLPalette, ents, 10);
CHECK_PREFIX(QXLQUICData, data, 4);
CHECK_PREFIX(QXLMonitorsConfig, heads, 4);
CHECK_PREFIX(SpiceSubMessageList, sub_messages, 2);
CHECK_PREFIX(StreamMsgDeviceDisplayInfo, device_address, 12);
CHECK_PREFIX(StreamMsgStartStop, codecs, 1);
CHECK_PREFIX(StreamMsgNotifyError, msg, 4);
CHECK_PREFIX(StreamMsgCursorSet, data, 12);

int main(void)
{
    const uint32_t monitor_count = 2;
    size_t message_size = sizeof(VDAgentMonitorsConfig) +
                          monitor_count * sizeof(VDAgentMonConfig);
    VDAgentMonitorsConfig *message = calloc(1, message_size);
    int status;

    if (message == NULL) {
        return 1;
    }

    message->num_of_monitors = monitor_count;
    message->monitors[0].width = 1920;
    message->monitors[1].width = 2560;
    message->monitors[1].x = 1920;

    status = message->monitors[0].width != 1920 ||
             message->monitors[1].width != 2560 ||
             message->monitors[1].x != 1920;
    free(message);
    return status;
}
