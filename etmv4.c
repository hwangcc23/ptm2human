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
    int index = 1, cnt;

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

/* FIXME: handle not only the instruction trace stream but also the data trace stream */
DECL_DECODE_FN(trace_info)
{
    int index = 1, i;
    unsigned int plctl = 0, info = 0, key = 0, spec = 0, cyct = 0;
    const unsigned char c_bit = 0x80;
    unsigned char data;

    for (i = 0; i < 4; i++) {
        data = pkt[index++];
        plctl |= (data & ~c_bit) << (7 * i);
        if (!(data & c_bit)) {
            break;
        }
    }
    if (i >= 1) {
        /* ETMv4 arch spec 6/228: A trace unit must not output more than 1 PLCTL field in a Trace info packet */
        LOGE("More than 1 PLCTL field in the trace info packet\n");
        return -1;
    } else {
        LOGD("[traceinfo] plctl = 0x%X\n", plctl);
    }

    if (plctl & 1) {
        /* the INFO section is present*/
        for (i = 0; i < 4; i++) {
            data = pkt[index++];
            info |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 1) {
            /* ETMv4 arch spec 6/228: A trace unit must not output more than 1 INFO field in a Trace info packet */
            LOGE("More than 1 INFO field in the trace info packet\n");
            return -1;
        } else {
            LOGD("[traceinfo] info = 0x%X\n", info);
        }
    }

    if (plctl & 2) {
        /* the KEY section is present*/
        for (i = 0; i < 4; i++) {
            data = pkt[index++];
            key |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 4) {
            /* 4 fileds are enough since p0_key_max is a 32-bit integer */
            LOGE("More than 4 KEY fields in the trace info packet\n");
            return -1;
        } else {
            LOGD("[traceinfo] key = 0x%X\n", key);
        }
    }

    if (plctl & 4) {
        /* the SPEC section is present*/
        for (i = 0; i < 4; i++) {
            data = pkt[index++];
            spec |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 4) {
            /* 4 fileds are enough since max_spec_depth is a 32-bit integer */
            LOGE("More than 4 SPEC fields in the trace info packet\n");
            return -1;
        } else {
            LOGD("[traceinfo] curr_spec_depth = 0x%X\n", spec);
        }
    }

    if (plctl & 8) {
        /* the CYCT section is present*/
        for (i = 0; i < 2; i++) {
            data = pkt[index++];
            cyct |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 2) {
            LOGE("More than 2 CYCT fields in the trace info packet\n");
            return -1;
        } else {
            LOGD("[traceinfo] cc_thresold = 0x%X\n", cyct);
        }
    }

    return index;
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
            if (p != 12)
                continue;
            c = stream->buff[i + 12];
            if ((c & PKT_NAME(trace_info).mask) == PKT_NAME(trace_info).val) {
                p = DECODE_FUNC_NAME(trace_info)((const unsigned char *)&(stream->buff[i + 12]), stream);
                if (p > 0) {
                    /* SYNCING -> INSYNC */
                    stream->state++;
                    return i;
                }
            }
        }
    }

    return -1;
}

#endif
