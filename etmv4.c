#include <stdio.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"
#include "config.h"

#if TRACE_STREAM_PROT == ETMV4_TRACE_STREAM

DEF_TRACEPKT(extension, 0xff, 0x00);
DEF_TRACEPKT(trace_info, 0xff, 0x01);

DECL_DECODE_FN(extension)
{
    int index, cnt;

    index = 1;

    switch (pkt[index]) {
    case 0:
        /* async */
        for (cnt = 0 ; (cnt < 11) & (index < stream->buff_len); cnt++, index++) {
            if (cnt == 10 && pkt[index] != 0x80)
                break;
            if (cnt != 10 && pkt[index] != 0)
                break;
        }
        if (cnt != 11) {
            LOGE("Payload bytes of async are not correct\n");
            LOGE("Invalid async packet\n");
            return -1;
        }
        LOGD("[async]\n");

        /* SYNCING -> INSYNC */
        stream->state++;

        break;

    case 3:
        /* discard */
        index++;
        LOGD("[discard]\n");
        /* TODO: add tracer function */
        break;

    case 5:
        /* overflow */
        index++;
        LOGD("[overflow]\n");
        /* TODO: add tracer function */
        break;

    default:
        LOGE("First payload byte of async is not correct\n");
        LOGE("Invalid async packet\n");
        index = -1;
        break;
    }

    return index;
}

DECL_DECODE_FN(trace_info)
{
    return -1;
}

struct tracepkt *etmv4pkts[] =
{
    &PKT_NAME(extension),
    &PKT_NAME(trace_info),
    NULL,
};

struct tracepkt **tracepkts = etmv4pkts;

int synchronization(struct stream *stream)
{
    int i, p;
    unsigned char c;

    for (i = 0; i < stream->buff_len; i++) {
        c = stream->buff[i];
        if ((c & PKT_NAME(extension).mask) == PKT_NAME(extension).val) {
            p = DECODE_FUNC_NAME(extension)((const unsigned char *)&(stream->buff[i]), stream);
            if ((p > 0) && (stream->state >= INSYNC)) {
                return i;
            }
        }
    }

    return -1;
}

#endif
