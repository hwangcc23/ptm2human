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
        } else if (pkt[index] == (char)0x80) {
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
        addr |= pkt[index] << (8 * i);
    }

    info = pkt[index++];
    reason = (info & 0x60) >> 5;

    /* 
     * The cycle count is present only when cycle-acculate tracing is enabled 
     * AND the reason code is not b00. 
     */
    if (stream->cycle_accurate && reason) {
        cyc_cnt = (pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index++] & 0x40) >> 6;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (pkt[index] & 0x7f) << (4 + 7 * (i - 1));
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
        contextid = pkt[index++];
        break;

    case 2:
        for (i = 0; i < 2; i++) {
            contextid |= pkt[index++] << (8 * i);
        }
        break;

    case 4:
        for (i = 0; i < 4; i++) {
            contextid |= pkt[index++] << (8 * i);
        }
        break;

    default:
        break;
    }

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

    return index;
}

DECL_DECODE_FN(atom)
{
    int i, c_bit, F_bit, index;
    unsigned int cyc_cnt;
    static const char F_bit_mask = 0x02, F_bit_shift = 1;

    if (stream->cycle_accurate) {
        index = 0;
        cyc_cnt = (pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index] & 0x40) >> 6;
        F_bit = (pkt[index++] & F_bit_mask) >> F_bit_shift;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (pkt[index] & 0x7f) << (4 + 7 * (i - 1));
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

    /* 
     * XXX: Only for ARM and Thumb state.
     */
    for (addr = 0, index = 0; index < 4; index++) {
        addr |= (pkt[index] & 0x7f) << (6 * index);

        if (!(pkt[index] & 0x80))
            break;
    }
    if (index == 4) {
        full_addr = 1;

        if (pkt[index] & 0x10) {
            /* Thumb state format */
            addr <<= 1;
            addr |= (pkt[index] & 0x0f) << 28;
            addr &= 0xfffffffe;
        } else {
            /* ARM state format */
            addr <<= 2;
            addr |= (pkt[index] & 0x07) << 29;
            addr &= 0xfffffffc;
        }

        if (pkt[index++] & 0x40) {
            have_exp = 1;
            NS = (pkt[index] & 0x01)? 1: 0;
            exp = (pkt[index] & 0x1E);
            if (pkt[index++] & 0x80) {
                Hyp = (pkt[index] & 0x20)? 1: 0;
                exp |= (pkt[index] & 0x1F) << 4;
            }
        }
    } else {
        full_addr = 0;
    }

    if (stream->cycle_accurate) {
        cyc_cnt = (pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index++] & 0x40) >> 6;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (pkt[index] & 0x7f) << (4 + 7 * (i - 1));
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
        OUTPUT("addr offset = 0x%x * n(n=4 for ARM state and n=2 for Thumb state), ", addr);
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
    int index, AltS = -1;
    unsigned int addr;

    for (addr = 0, index = 1; index < 5; index++) {
        addr |= (pkt[index] & 0x7f) << (6 * (index - 1));

        if (!(pkt[index] & 0x80))
            break;
    }
    if (index == 5) {
        if (pkt[index] & 0x10) {
            /* Thumb state format */
            addr <<= 1;
            addr |= (pkt[index] & 0x0f) << 28;
            addr &= 0xfffffffe;
            if (pkt[index++] & 0x40) {
                AltS = (pkt[index] & 0x40)? 1: 0;
                index++;
            }
        } else {
            /* ARM state format */
            addr <<= 2;
            addr |= (pkt[index] & 0x07) << 29;
            addr &= 0xfffffffc;
            if (pkt[index++] & 0x40) {
                index++;
            }
        }
    }

    OUTPUT("[waypoint update] addr = 0x%x, ", addr);
    if (AltS != -1) {
        OUTPUT(" AltS = %d, ", AltS);
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
        contextid = pkt[index++];
        break;

    case 2:
        for (i = 0; i < 2; i++) {
            contextid |= pkt[index++] << (8 * i);
        }
        break;

    case 4:
        for (i = 0; i < 4; i++) {
            contextid |= pkt[index++] << (8 * i);
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
        timestamp |= (pkt[index] & 0x7f) << (7 * (index - 1));
        if (pkt[index] & 0x80) {
            break;
        }
    }
    if (index == 9) {
        timestamp |= (unsigned long long)(pkt[index]) << 56;
        index++;
    }

    if (stream->cycle_accurate) {
        cyc_cnt = (pkt[index] & 0x3c) >> 2;
        c_bit = (pkt[index++] & 0x40) >> 6;
        LOGD("cyc_cnt = 0x%x, c_bit = %d\n", cyc_cnt, c_bit); 
        if (c_bit) {
            for (i = 1; i < 5; i++) {
                cyc_cnt |= (pkt[index] & 0x7f) << (4 + 7 * (i - 1));
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
