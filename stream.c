#include <stdio.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"

int decode_stream(struct stream *stream)
{
    int cur, i, ret;

    if (!stream) {
        LOGE("Invalid struct stream pointer\n");
        return -1;
    }
    if (stream->state == READING) {
        /* READING -> SYNCING */
        stream->state++;
    } else {
        LOGE("Stream state is not correct\n");
        return -1;
    }

    LOGV("Syncing the trace stream...\n");
    cur = synchronization(stream);
    if (cur < 0) {
        LOGE("Cannot find any synchronization packet\n");
        return -1;
    } else {
        LOGD("Trace starts from offset %d\n", cur);
    }

    LOGV("Decoding the trace stream...\n");
    /* INSYNC -> DECODING */
    stream->state++;
    for (; cur < stream->buff_len; ) {
        char c = stream->buff[cur];

        LOGD("Got a packet header 0x%02x at offset %d\n", c, cur);

        for (i = 0; tracepkts[i]; i++) {
            if ((c & tracepkts[i]->mask) == tracepkts[i]->val) {
                LOGD("Get a packet of type %s\n", tracepkts[i]->name);
                break;
            }
        }
        if (!tracepkts[i]) {
            LOGE("Cannot recognize a packet header 0x%02x\n", c);
            LOGE("Proceed on guesswork\n");
            cur++;
            continue;
        }

        ret = tracepkts[i]->decode((const unsigned char *)&(stream->buff[cur]), stream);
        if (ret <= 0) {
            LOGE("Cannot decode a packet of type %s at offset %d\n", tracepkts[i]->name, cur);
            LOGE("Proceed on guesswork\n");
            cur++;
        } else {
            cur += ret;
        }
    }

    LOGV("Complete decode of the trace stream\n");

    return 0;
}
