#include <stdio.h>
#include "output.h"
#include "log.h"
#include "stream.h"
#include "pftproto.h"

DEF_PFTPKT(async, 0xff, 0x00);
DEF_PFTPKT(isync, 0xff, 0x08);
DEF_PFTPKT(atom, 0x81, 0x80);
DEF_PFTPKT(branch_addr, 0x01, 0x01);
DEF_PFTPKT(waypoint_update, 0xff, 0x72);
DEF_PFTPKT(trigger, 0xff, 0x0c);
DEF_PFTPKT(contextid, 0xff, 0x6e);
DEF_PFTPKT(vmid, 0xff, 0x3c);
DEF_PFTPKT(timestamp, 0xfb, 0x42);
DEF_PFTPKT(exception_return, 0xff, 0x76);
DEF_PFTPKT(ignore, 0xff, 0x66);

DECL_DECODE_FN(async)
{
    int index;

    /* continue until reach the end packet with the binary value b10000000 */
    for (index = 1; index < stream->buff_len; index++) {
        if (pkt[index] == 0x00) {
            continue;
        } else if (pkt[index] == (unsigned char)0x80) {
            OUTPUT("[a-sync]\n");
            index++;
            break;
        } else {
            LOGE("Invalid a-sync packet\n");
            index = -1;
            break;
        }
    }
    if (index == stream->buff_len) {
        LOGE("Invalid a-sync packet\n");
        index = -1;
    }

    return index;
}

DECL_DECODE_FN(isync)
{
    int i, index, c_bit, reason;
    unsigned int addr = 0, info, cyc_cnt = 0, contextid = 0;
 
    for (i = 0, index = 1; i < 4; i++, index++) {
        addr |= (unsigned int)(pkt[index]) << (8 * i);
    }

    info = pkt[index++];
    reason = (info & 0x60) >> 5;

    /* 
     * The cycle count is present only when cycle-acculate tracing is enabled 
     * AND the reason code is not b00. 
     */
    if (stream->cycle_accurate && reason) {
        cyc_cnt = (unsigned int)(pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index++] & 0x40) >> 6;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (unsigned int)(pkt[index] & 0x7f) << (4 + 7 * (i - 1));
                c_bit = (pkt[index++] & 0x80)? 1: 0;
                LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
                if (!c_bit) {
                    break;
                }
            }
        }
    }

    switch (stream->contextid_size) {
    case 1:
        contextid = (unsigned int)(pkt[index++]);
        break;

    case 2:
        for (i = 0; i < 2; i++) {
            contextid |= (unsigned int)(pkt[index++]) << (8 * i);
        }
        break;

    case 4:
        for (i = 0; i < 4; i++) {
            contextid |= (unsigned int)(pkt[index++]) << (8 * i);
        }
        break;

    default:
        break;
    }

    if (stream->state >= DECODING) {
        OUTPUT("[i-sync] addr = 0x%x (%s), ", addr & ~0x1, (addr & 0x1)? "thumb": "arm");
        OUTPUT("info = |reason %d|NS %d|AltIS %d|Hyp %d|, ",  \
                    reason, \
                    (info & 0x08)? 1: 0,    \
                    (info & 0x04)? 1: 0,    \
                    (info & 0x02)? 1: 0);
        if (stream->cycle_accurate) {
            OUTPUT("cycle count = 0x%x, ", cyc_cnt);
        }
        if (stream->contextid_size) {
            OUTPUT("context id = 0x%x, ", contextid);
        }
        OUTPUT("\n");
    }

    return index;
}

DECL_DECODE_FN(atom)
{
    int i, c_bit, F_bit, index;
    unsigned int cyc_cnt;
    static const char F_bit_mask = 0x02, F_bit_shift = 1;

    if (stream->cycle_accurate) {
        index = 0;
        cyc_cnt = (unsigned int)(pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index] & 0x40) >> 6;
        F_bit = (pkt[index++] & F_bit_mask) >> F_bit_shift;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (unsigned int)(pkt[index] & 0x7f) << (4 + 7 * (i - 1));
                c_bit = (pkt[index++] & 0x80)? 1: 0;
                LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
                if (!c_bit) {
                    break;
                }
            } 
        }

        OUTPUT("[%s atom] cycle count = 0x%x\n", (F_bit)? "N": "E", cyc_cnt);

        return index;
    } else {
        for (i = 1; i < 7; i++) {
            if (pkt[0] & (1 << i)) {
                OUTPUT("[N atom]\n");
            } else {
                OUTPUT("[E atom]\n");
            }
        }

        return 1;
    }
}

DECL_DECODE_FN(branch_addr)
{
    int index, full_addr, have_exp = 0, NS = 0, Hyp = 0, i, c_bit;
    unsigned int addr, exp = 0, cyc_cnt = 0;

    index = 0;
    addr = 0;
    full_addr = 0;
    do {
        if (index == 0) {
            addr = (unsigned int)(pkt[index] & 0x7e) >> 1;
            if (!(pkt[index++] & 0x80)) {
                break;
            }
        } else if (index >= 1 && index <= 3) {
            addr |= (unsigned int)(pkt[index] & 0x7f) << (6 + 7 * (index - 1));
            if (!(pkt[index++] & 0x80)) {
                break;
            }
        } else if (index == 4) {
            full_addr = 1;
            if (pkt[index] & 0x20) {
                /* Jazelle state */
                addr |= (unsigned int)(pkt[index] & 0x1f) << 27;
            } else if (pkt[index] & 0x10) {
                /* Thumb state */
                addr |= (unsigned int)(pkt[index] & 0x0f) << 27;
                addr <<= 1;
            } else {
                /* ARM state */
                addr |= (unsigned int)(pkt[index] & 0x07) << 27;
                addr <<= 2;
            }
            if (!(pkt[index++] & 0x40)) {
                break;
            } else {
                have_exp = 1;
                NS = (pkt[index] & 0x01)? 1: 0;
                exp = (pkt[index] & 0x1E);
                if (pkt[index++] & 0x80) {
                    Hyp = (pkt[index] & 0x20)? 1: 0;
                    exp |= (pkt[index] & 0x1F) << 4;
                }
            }
        }
    } while (index < 5);

    if (stream->cycle_accurate) {
        cyc_cnt = (unsigned int)(pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index++] & 0x40) >> 6;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (unsigned int)(pkt[index] & 0x7f) << (4 + 7 * (i - 1));
                c_bit = (pkt[index++] & 0x80)? 1: 0;
                LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
                if (!c_bit) {
                    break;
                }
            }
        }
    }

    OUTPUT("[branch address] ");
    if (full_addr) {
        OUTPUT("addr = 0x%x, ", addr);
    } else {
        OUTPUT("addr change = 0x%x * n (n=4 for ARM state, n=2 for Thumb state), ", addr);
    }
    if (have_exp) {
        OUTPUT("info = |exception %d|NS %d|Hyp %d|, ", exp, NS, Hyp);
    }
    if (stream->cycle_accurate) {
        OUTPUT("cycle count = 0x%x, ", cyc_cnt);
    }
    OUTPUT("\n");

    return index;
}

DECL_DECODE_FN(waypoint_update)
{
    int index, full_addr, AltS = -1;
    unsigned int addr;

    index = 1;
    addr = 0;
    full_addr = 0;
    do {
        if (index == 1) {
            addr = (unsigned int)(pkt[index] & 0x7e) >> 1;
            if (!(pkt[index++] & 0x80)) {
                break;
            }
        } else if (index >= 2 && index <= 4) {
            addr |= (unsigned int)(pkt[index] & 0x7f) << (6 + 7 * (index - 2));
            if (!(pkt[index++] & 0x80)) {
                break;
            }
        } else if (index == 5) {
            full_addr = 1;
            if (pkt[index] & 0x10) {
                /* Thumb state */
                addr |= (unsigned int)(pkt[index] & 0x0f) << 27;
                addr <<= 1;
                if (pkt[index++] & 0x40) {
                    AltS = (pkt[index] & 0x40)? 1: 0;
                    index++;
                    break;
                }
            } else {
                /* ARM state */
                addr |= (unsigned int)(pkt[index] & 0x07) << 27;
                addr <<= 2;
                if (pkt[index++] & 0x40) {
                    index++;
                    break;
                }
            }
        }
    } while (index < 7);

    OUTPUT("[waypoint update] ");
    if (full_addr) {
        OUTPUT("addr = 0x%x, ", addr);
    } else {
        OUTPUT("addr change = 0x%x * n(n=4 for ARM state and n=2 for Thumb state) ", addr);
    }
    if (AltS != -1) {
        OUTPUT("AltS = %d, ", AltS);
    }
    OUTPUT("\n");

    return index;
}

DECL_DECODE_FN(trigger)
{
    OUTPUT("[trigger]\n");

    return 1;
}

DECL_DECODE_FN(contextid)
{
    unsigned int contextid = 0;
    int i, index = 1;

    switch (stream->contextid_size) {
    case 1:
        contextid = (unsigned int)(pkt[index++]);
        break;

    case 2:
        for (i = 0; i < 2; i++) {
            contextid |= (unsigned int)(pkt[index++]) << (8 * i);
        }
        break;

    case 4:
        for (i = 0; i < 4; i++) {
            contextid |= (unsigned int)(pkt[index++]) << (8 * i);
        }
        break;

    default:
        break;
    }

    OUTPUT("[context ID] context ID = 0x%x\n", contextid);

    return index;
}

DECL_DECODE_FN(vmid)
{
    OUTPUT("[VMID] VMID = 0x%02x\n", pkt[1]);

    return 1;
}

DECL_DECODE_FN(timestamp)
{
    unsigned long long timestamp;
    int index, c_bit, i;
    unsigned int cyc_cnt = 0;

    for (index = 1, timestamp = 0; index < 9; index++) {
        timestamp |= (unsigned long long)(pkt[index] & 0x7f) << (7 * (index - 1));
        if (!(pkt[index] & 0x80)) {
            index++;
            break;
        }
    }
    if (index == 9) {
        timestamp |= (unsigned long long)(pkt[index]) << 56;
        index++;
    }

    if (stream->cycle_accurate) {
        cyc_cnt = (unsigned int)(pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index++] & 0x40) >> 6;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (unsigned int)(pkt[index] & 0x7f) << (4 + 7 * (i - 1));
                c_bit = (pkt[index++] & 0x80)? 1: 0;
                LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
                if (!c_bit) {
                    break;
                }
            }
        }
    }

    OUTPUT("[timestamp] timestamp = 0x%llx ", timestamp);
    if (stream->cycle_accurate) {
        OUTPUT("cycle count = 0x%x, ", cyc_cnt);
    }
    OUTPUT("\n");

    return index;
}

DECL_DECODE_FN(exception_return)
{
    OUTPUT("[exception return]\n");

    return 1;
}

DECL_DECODE_FN(ignore)
{
    OUTPUT("[ignore]\n");

    return 1;
}

int synchronization(struct stream *stream)
{
    int i, p;
    unsigned char c;

    for (i = 0; i < stream->buff_len; i++) {
        c = stream->buff[i];
        if ((c & PKT_NAME(isync).mask) == PKT_NAME(isync).val) {
            p = DECODE_FUNC_NAME(isync)((const unsigned char *)&(stream->buff[i]), stream);
            if (p > 0) {
                /* SYNCING -> INSYNC */
                stream->state++;
                return i;
            }
        }
    }

    return -1;
}

struct pftpkt *pftpkts[] =
{
    &PKT_NAME(async),
    &PKT_NAME(isync),
    &PKT_NAME(atom),
    &PKT_NAME(branch_addr),
    &PKT_NAME(waypoint_update),
    &PKT_NAME(trigger),
    &PKT_NAME(contextid),
    &PKT_NAME(vmid),
    &PKT_NAME(timestamp),
    &PKT_NAME(exception_return),
    &PKT_NAME(ignore),
    NULL,
};
