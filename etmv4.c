#include <stdio.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"
#include "config.h"

#if TRACE_STREAM_PROT == ETMV4_TRACE_STREAM

DEF_TRACEPKT(extension, 0xff, 0x00);
DEF_TRACEPKT(trace_info, 0xff, 0x01);
DEF_TRACEPKT(trace_on, 0xff, 0x04);
DEF_TRACEPKT(timestamp, 0xfe, 0x02);
DEF_TRACEPKT(exception, 0xfe, 0x06);
DEF_TRACEPKT(cc_format_1, 0xfe, 0x0e);
DEF_TRACEPKT(cc_format_2, 0xfe, 0x0c);
DEF_TRACEPKT(cc_format_3, 0xf0, 0x10);

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
        LOGD("[trace info] plctl = 0x%X\n", plctl);
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
            LOGD("[trace info] info = 0x%X\n", info);
        }
        TRACE_INFO(stream) = info;
    } else {
        TRACE_INFO(stream) = 0;
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
            LOGD("[trace info] key = 0x%X\n", key);
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
            LOGD("[trace info] curr_spec_depth = 0x%X\n", spec);
        }
        CURR_SPEC_DEPTH(stream) = spec;
    } else {
        CURR_SPEC_DEPTH(stream) = 0;
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
            LOGD("[trace info] cc_thresold = 0x%X\n", cyct);
        }
        CC_THRESHOLD(stream) = cyct;
    } else {
        CC_THRESHOLD(stream) = 0;
    }

    return index;
}

DECL_DECODE_FN(trace_on)
{
    LOGD("[trace on]\n");
    return 1;
}

DECL_DECODE_FN(timestamp)
{
    int index, i;
    unsigned long long ts = 0;
    unsigned char data;
    const unsigned char c_bit = 0x80;
    unsigned int count = 0;

    for (index = 1, i = 0; index < 10; index++, i++) {
        data = pkt[index];
        ts |= (data & ~c_bit) << (7 * i);
        if ((index != 9) && !(data & c_bit)) {
            break;
        }
    }

    if (pkt[0] & 1) {
        /* cycle count section is present since the N bit in the header is 1'b1 */
        for (i = 0; i < 3; index++, i++) {
            data = pkt[index];
            count |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
    }

    LOGD("[timestemp] timestamp = %llu, cycle count = %d\n", ts, count);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(exception)
{
    int index = 0;
    unsigned char data1, data2 = 0;
    const unsigned char c_bit = 0x80;

    if (pkt[index++] & 1) {
        /* exception return packet */
        LOGD("[exception return]\n");
    } else {
        /* exception patcket */
        data1 = pkt[index++];
        if (data1 & c_bit) {
            data2 = pkt[index++];
        }
        LOGD("[exception] E1:E0 = %d, TYPE = 0x%02X, P = %d\n",
                ((data1 & 0x40) >> 5) | (data1 & 0x01),
                ((data1 & 0x3E) >> 1) | (data2 & 0x1F),
                (data2 & 0x20) >> 5);

        /* TODO: add decoding for the address packet */
    }

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(cc_format_1)
{
    int index = 0, i;
    int u_bit = pkt[index++];
    unsigned char data;
    const unsigned char c_bit = 0x80;
    unsigned int commit = 0, count = 0;

    /* FIXME: need to get TRCIDR0.COMMOPT */
    if (1) {
        for (i = 0; i < 4; i++, index++) {
            data = pkt[index];
            commit |= (data & ~c_bit) << (7 * i);
            if (!(c_bit)) {
                break;
            }
        }
        if (i >= 4) {
            LOGE("More than 4 bytes of the commit section in the cycle count format 1 packet");
            return -1;
        }
    }

    if (!u_bit) {
        for (i = 0; i < 3; i++, index++) {
            data = pkt[index];
            count |= (data & ~c_bit) << (7 * i);
            if (!(c_bit)) {
                break;
            }
        }
        if (i >= 3) {
            LOGE("More than 3 bytes of the cycle count section in the cycle count format 1 packet");
            return -1;
        }
    }

    LOGD("[cycle count format 1] U = %d, COMMIT = %d, COUNT = %d\n", u_bit, commit, count);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(cc_format_2)
{
    LOGD("[cycle count format 2] F = %d, AAAA = %d, BBBB = %x\n",
            pkt[0] & 0x01,
            (pkt[1] & 0xf0) >> 4, (pkt[1] & 0x0f));

    /* TODO: add trace function */

    return 2;
}

DECL_DECODE_FN(cc_format_3)
{
    LOGD("[cycle count format 3] AA = %d, BB = %x\n", (pkt[0] & 0x0c) >> 2, (pkt[0] & 0x03));

    /* TODO: add trace function */

    return 1;
}

struct tracepkt *etmv4pkts[] =
{
    &PKT_NAME(extension),
    &PKT_NAME(trace_info),
    &PKT_NAME(trace_on),
    &PKT_NAME(timestamp),
    &PKT_NAME(exception),
    &PKT_NAME(cc_format_1),
    &PKT_NAME(cc_format_2),
    &PKT_NAME(cc_format_3),
    NULL,
};

struct tracepkt **tracepkts = etmv4pkts;

int synchronization(struct stream *stream)
{
    int i, p;
    unsigned char c;

    /* locate an async packet and search for a trace-info packet */
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
