/*
 * etmv4.c: Decoding functions of ETMv4 packets
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <stdio.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"

static const unsigned char c_bit = 0x80;

DEF_TRACEPKT(extension, 0xff, 0x00);
DEF_TRACEPKT(trace_info, 0xff, 0x01);
DEF_TRACEPKT(trace_on, 0xff, 0x04);
DEF_TRACEPKT(timestamp, 0xfe, 0x02);
DEF_TRACEPKT(exception, 0xfe, 0x06);
DEF_TRACEPKT(cc_format_1, 0xfe, 0x0e);
DEF_TRACEPKT(cc_format_2, 0xfe, 0x0c);
DEF_TRACEPKT(cc_format_3, 0xf0, 0x10);
DEF_TRACEPKT(data_sync_marker, 0xf0, 0x20);
DEF_TRACEPKT(commit, 0xff, 0x2d);
DEF_TRACEPKT(cancel_format_1, 0xfe, 0x2e);
DEF_TRACEPKT(cancel_format_2, 0xfc, 0x34);
DEF_TRACEPKT(cancel_format_3, 0xf8, 0x38);
DEF_TRACEPKT(mispredict, 0xfc, 0x30);
DEF_TRACEPKT(cond_inst_format_1, 0xff, 0x6c);
DEF_TRACEPKT(cond_inst_format_2, 0xfc, 0x40);
DEF_TRACEPKT(cond_inst_format_3, 0xff, 0x6d);
DEF_TRACEPKT(cond_flush, 0xff, 0x43);
DEF_TRACEPKT(cond_result_format_1, 0xf8, 0x68);
DEF_TRACEPKT(cond_result_format_2, 0xf8, 0x48);
DEF_TRACEPKT(cond_result_format_3, 0xf0, 0x50);
DEF_TRACEPKT(cond_result_format_4, 0xfc, 0x44);
DEF_TRACEPKT(event, 0xf0, 0x70);
DEF_TRACEPKT(short_address_is0, 0xff, 0x95);
DEF_TRACEPKT(short_address_is1, 0xff, 0x96);
DEF_TRACEPKT(long_address_32bit_is0, 0xff, 0x9a);
DEF_TRACEPKT(long_address_32bit_is1, 0xff, 0x9b);
DEF_TRACEPKT(long_address_64bit_is0, 0xff, 0x9d);
DEF_TRACEPKT(long_address_64bit_is1, 0xff, 0x9e);
DEF_TRACEPKT(exact_match_address, 0xfc, 0x90);
DEF_TRACEPKT(context, 0xfe, 0x80);
DEF_TRACEPKT(address_context_32bit_is0, 0xff, 0x82);
DEF_TRACEPKT(address_context_32bit_is1, 0xff, 0x83);
DEF_TRACEPKT(address_context_64bit_is0, 0xff, 0x85);
DEF_TRACEPKT(address_context_64bit_is1, 0xff, 0x86);
DEF_TRACEPKT(atom_format_1, 0xfe, 0xf6);
DEF_TRACEPKT(atom_format_2, 0xfe, 0xd8);
DEF_TRACEPKT(atom_format_3, 0xfe, 0xf8);
DEF_TRACEPKT(atom_format_4, 0xfe, 0xdc);
DEF_TRACEPKT(atom_format_5, 0xd4, 0xd4);
DEF_TRACEPKT(atom_format_6, 0xc0, 0xc0);
DEF_TRACEPKT(q, 0xf0, 0xa0);

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

DECL_DECODE_FN(trace_info)
{
    int index = 1, i;
    unsigned int plctl = 0, info = 0, key = 0, spec = 0, cyct = 0;
    unsigned char data;

    /* TODO: refactor the following code into a reusable function */
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

    RESET_ADDRESS_REGISTER(stream);

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
    unsigned int count = 0;

    for (index = 1, i = 0; index < 10; i++) {
        data = pkt[index++];
        ts |= (data & ~c_bit) << (7 * i);
        if ((index != 9) && !(data & c_bit)) {
            break;
        }
    }

    if (pkt[0] & 1) {
        /* cycle count section is present since the N bit in the header is 1'b1 */
        for (i = 0; i < 3; i++) {
            data = pkt[index++];
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
    unsigned int commit = 0, count = 0;

    /* FIXME: need to get TRCIDR0.COMMOPT */
    if (1) {
        for (i = 0; i < 4; i++) {
            data = pkt[index++];
            commit |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 4) {
            LOGE("More than 4 bytes of the commit section in the cycle count format 1 packet");
            return -1;
        }
    }

    if (!u_bit) {
        for (i = 0; i < 3; i++) {
            data = pkt[index++];
            count |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
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

DECL_DECODE_FN(data_sync_marker)
{
    if (pkt[0] & 0x08) {
        /* unnumbered data synchronization marker */
        LOGD("[unnumbered data sync maker] A = %d\n", pkt[0] & 0x07);
    } else {
        /* Numbered data synchronization marker */
        LOGD("[numbered data sync maker] NUM = %d\n", pkt[0] & 0x07);
    }

    return 1;
}

DECL_DECODE_FN(commit)
{
    int index, i;
    unsigned char data;
    unsigned int commit = 0;

    for (index = 1, i = 0; i < 4; i++) {
        data = pkt[index++];
        commit |= (data & ~c_bit) << (7 * i);
        if (!(data & c_bit)) {
            break;
        }
    }
    if (i >= 4) {
        LOGE("More than 4 bytes of the commit section in the commit packet");
        return -1;
    }
    LOGD("[commit] COMMIT = %d\n", commit);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(cancel)
{
    int index = 0, i;
    unsigned char data;
    unsigned int cancel = 0;

    if (!(pkt[index] & 0x10)) {
        /* cancle format 1 */
        for (index = 1, i = 0; i < 4; i++) {
            data = pkt[index++];
            cancel |= (data & ~c_bit) << (7 * i);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 4) {
            LOGE("More than 4 bytes of the cancel section in the cancel format 1 packet");
            return -1;
        }
        LOGD("[cancel format 1] M = %d, CANCEL = %d\n", pkt[0] & 0x01, cancel);
    } if (!(pkt[index] & 0x80)) {
        /* cancle format 2 */
        index++;
        LOGD("[cancel format 2] A = %d\n", pkt[index] & 0x03);
    } else {
        /* cancle format 3 */
        index++;
        LOGD("[cancel format 3] CC = %d, A = %d\n", (pkt[index] & 0x06) >> 1, pkt[index] & 0x01);
    }

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(cancel_format_1)
{
    return decode_cancel(pkt, stream);
}

DECL_DECODE_FN(cancel_format_2)
{
    return decode_cancel(pkt, stream);
}

DECL_DECODE_FN(cancel_format_3)
{
    return decode_cancel(pkt, stream);
}

DECL_DECODE_FN(mispredict)
{
    LOGD("[mispredict] A = %d\n", pkt[0] & 0x03);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(cond_inst_format_1)
{
    int index, i;
    unsigned char data;
    unsigned int key = 0;

    for (index = 1, i = 0; i < 4; i++) {
        data = pkt[index++];
        key |= (data & ~c_bit) << (7 * i);
        if (!(data & c_bit)) {
            break;
        }
    }
    if (i >= 4) {
        LOGE("More than 4 bytes of the commit section in the commit packet");
        return -1;
    }
    LOGD("[conditional instruction format 1] key = %d\n", key);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(cond_inst_format_2)
{
    int ci;

    ci = pkt[0] & 0x03;
    LOGD("[conditional instruction format 2] ci = %d\n", ci);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(cond_inst_format_3)
{
    int z, num;

    z = pkt[1] & 0x01;
    num = (pkt[1] & 0x7E) >> 1;
    LOGD("[conditional instruction format 3] z = %d, num = %d\n", z, num);

    /* TODO: add trace function */

    return 2;
}

DECL_DECODE_FN(cond_flush)
{
    LOGD("[conditional flush]\n");

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(cond_result_format_1)
{
    int index = 0, nr_payloads, payload, i;
    unsigned char data;
    unsigned int result[2], key[2];

    nr_payloads = (pkt[index++] & 0x4)? 1: 2;

    for (payload = 0; payload < nr_payloads; payload++) {
        result[payload] = pkt[index] & 0x0f;
        key[payload] = (pkt[index] >> 4) & 0x7;
        for (index++, i = 0; i < 5; i++) {
            data = pkt[index++];
            key[payload] |= (data & ~c_bit) << (7 * i + 3);
            if (!(data & c_bit)) {
                break;
            }
        }
        if (i >= 5) {
            LOGE("More than 5 payload bytes in the conditional result format 1 packet");
            return -1;
        }
        LOGD("[conditional result format 1] ci[%d] = %d, result[%d] = 0x%X, key[%d] = %d\n",
                payload, (payload == 0)? (pkt[0] & 0x1): ((pkt[1] & 0x2) >> 1),
                payload, result[payload],
                payload, key[payload]);
    }

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(cond_result_format_2)
{
    LOGD("[conditional result format 2] k = %d, t = 0x%X\n",
            (pkt[0] >> 2) & 0x1,
            (pkt[0] & 0x3));

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(cond_result_format_3)
{
    LOGD("[conditional result format 3] token = 0x%X\n",
            pkt[1] | ((pkt[0] & 0x0F) << 8));

    /* TODO: add trace function */

    return 2;
}

DECL_DECODE_FN(cond_result_format_4)
{
    LOGD("[conditional result format 4] t = 0x%X\n",
            (pkt[0] & 0x3));

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(event)
{
    LOGD("[event] EVENT = 0x%X\n", pkt[0] & 0x0F);

    return 1;
}

static void update_address_regs(struct stream * stream, unsigned long long address, int IS)
{
    ADDRESS_REGISTER(stream)[2] = ADDRESS_REGISTER(stream)[1];
    ADDRESS_REGISTER(stream)[1] = ADDRESS_REGISTER(stream)[0];
    ADDRESS_REGISTER(stream)[0].address = address;
    ADDRESS_REGISTER(stream)[0].IS = IS;
}

DECL_DECODE_FN(short_address)
{
    int index = 0, IS;
    unsigned long long address;

    address = ADDRESS_REGISTER(stream)[0].address;
    IS = (pkt[index++] & 0x01)? ADDR_REG_IS0: ADDR_REG_IS1;

    if (IS == ADDR_REG_IS0) {
        address &= ~0x000001FFLL;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
        if (pkt[1] & c_bit) {
            address &= ~0x0001FE00LL;
            address |= (unsigned long long)pkt[index++] << 9;
        }
    } else {
        address &= ~0x000000FFLL;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
        if (pkt[1] & c_bit) {
            address &= ~0x0000FF00LL;
            address &= (unsigned long long)pkt[index++] << 8;
        }
    }

    update_address_regs(stream, address, IS);

    LOGD("[short address] address = 0x%016llx, IS = %d\n", address, IS);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(short_address_is0)
{
    return decode_short_address(pkt, stream);
}

DECL_DECODE_FN(short_address_is1)
{
    return decode_short_address(pkt, stream);
}

DECL_DECODE_FN(long_address)
{
    int index = 1, IS;
    unsigned long long address;

    address = ADDRESS_REGISTER(stream)[0].address;

    switch (pkt[0]) {
    case 0x9a:
        IS = ADDR_REG_IS0;
        address &= ~0xFFFFFFFFLL;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 9;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        break;

    case 0x9b:
        IS = ADDR_REG_IS1;
        address &= ~0xFFFFFFFFLL;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
        address |= (unsigned long long)pkt[index++] << 8;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        break;

    case 0x9d:
        IS = ADDR_REG_IS0;
        address = 0;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 9;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        address |= (unsigned long long)pkt[index++] << 32;
        address |= (unsigned long long)pkt[index++] << 40;
        break;

    case 0x9e:
        IS = ADDR_REG_IS1;
        address = 0;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
        address |= (unsigned long long)pkt[index++] << 8;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        address |= (unsigned long long)pkt[index++] << 32;
        address |= (unsigned long long)pkt[index++] << 40;
        break;

    default:
        return -1;
    }

    update_address_regs(stream, address, IS);

    LOGD("[long address] address = 0x%016llx, IS = %d\n", address, IS);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(long_address_32bit_is0)
{
    return decode_long_address(pkt, stream);
}

DECL_DECODE_FN(long_address_32bit_is1)
{
    return decode_long_address(pkt, stream);
}

DECL_DECODE_FN(long_address_64bit_is0)
{
    return decode_long_address(pkt, stream);
}

DECL_DECODE_FN(long_address_64bit_is1)
{
    return decode_long_address(pkt, stream);
}

DECL_DECODE_FN(exact_match_address)
{
    int QE = pkt[0] & 0x03;

    LOGD("[Exact match address] QE = %d, address = 0x%016llx, IS = %d\n", QE,
            ADDRESS_REGISTER(stream)[QE].address, ADDRESS_REGISTER(stream)[QE].IS);

    update_address_regs(stream, ADDRESS_REGISTER(stream)[QE].address,
                                ADDRESS_REGISTER(stream)[QE].IS);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(context)
{
    int index = 0, EL, SF, NS, V = 0, C = 0;
    unsigned char data, VMID = 0;
    unsigned int CONTEXTID = 0;

    data = pkt[index++];
    if (data & 1) {
        data = pkt[index++];
        EL = data & 0x3;
        SF = (data & 0x10) >> 4;
        NS = (data & 0x20) >> 5;
        if (data & 0x40) {
            V = 1;
            VMID = pkt[index++];
        }
        if (data & 0x80) {
            C = 1;
            CONTEXTID = pkt[index++];
            CONTEXTID |= pkt[index++] << 8;
            CONTEXTID |= pkt[index++] << 16;
            CONTEXTID |= pkt[index++] << 24;
        }
        LOGD("[context] P = 1'b1, EL = %d, SF = %d, NS = %d, V = %d, C = %d, VMID = %d, CONTEXTID = 0x%04X\n", EL, SF, NS, V, C, VMID, CONTEXTID);
    } else {
        LOGD("[context] P = 1'b0\n");
    }

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(address_context)
{
    int index = 1, IS;
    unsigned long long address;
    int EL, SF, NS, V = 0, C = 0;
    unsigned char data, VMID = 0;
    unsigned int CONTEXTID = 0;

    address = ADDRESS_REGISTER(stream)[0].address;

    switch (pkt[0]) {
    case 0x82:
        IS = ADDR_REG_IS0;
        address &= ~0xFFFFFFFFLL;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 9;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        break;

    case 0x83:
        IS = ADDR_REG_IS1;
        address &= ~0xFFFFFFFFLL;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
        address |= (unsigned long long)pkt[index++] << 8;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        break;

    case 0x85:
        IS = ADDR_REG_IS0;
        address = 0;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 9;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        address |= (unsigned long long)pkt[index++] << 32;
        address |= (unsigned long long)pkt[index++] << 40;
        break;

    case 0x86:
        IS = ADDR_REG_IS1;
        address = 0;
        address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
        address |= (unsigned long long)pkt[index++] << 8;
        address |= (unsigned long long)pkt[index++] << 16;
        address |= (unsigned long long)pkt[index++] << 24;
        address |= (unsigned long long)pkt[index++] << 32;
        address |= (unsigned long long)pkt[index++] << 40;
        break;

    default:
        return -1;
    }

    update_address_regs(stream, address, IS);

    data = pkt[index++];
    EL = data & 0x3;
    SF = (data & 0x10) >> 4;
    NS = (data & 0x20) >> 5;
    if (data & 0x40) {
        V = 1;
        VMID = pkt[index++];
    }
    if (data & 0x80) {
        C = 1;
        CONTEXTID = pkt[index++];
        CONTEXTID |= pkt[index++] << 8;
        CONTEXTID |= pkt[index++] << 16;
        CONTEXTID |= pkt[index++] << 24;
    }

    LOGD("[address with context] address = 0x%016llx, IS = %d, EL = %d, SF = %d, NS = %d, V = %d, C = %d, VMID = %d, CONTEXTID = 0x%04X\n", address, IS, EL, SF, NS, V, C, VMID, CONTEXTID);

    /* TODO: add trace function */

    return index;
}

DECL_DECODE_FN(address_context_32bit_is0)
{
    return decode_address_context(pkt, stream);
}

DECL_DECODE_FN(address_context_32bit_is1)
{
    return decode_address_context(pkt, stream);
}

DECL_DECODE_FN(address_context_64bit_is0)
{
    return decode_address_context(pkt, stream);
}

DECL_DECODE_FN(address_context_64bit_is1)
{
    return decode_address_context(pkt, stream);
}

DECL_DECODE_FN(atom_format_1)
{
    int A;

    A = pkt[0] & 0x01;
    LOGD("[atom format 1] A = %d\n", A);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(atom_format_2)
{
    int A;

    A = pkt[0] & 0x03;
    LOGD("[atom format 2] A = %d\n", A);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(atom_format_3)
{
    int A;

    A = pkt[0] & 0x07;
    LOGD("[atom format 3] A = %d\n", A);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(atom_format_4)
{
    int A;

    A = pkt[0] & 0x03;
    LOGD("[atom format 4] A = %d\n", A);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(atom_format_5)
{
    unsigned int ABC;

    ABC = ((pkt[0] >> 3) & 0x04) | (pkt[0] & 0x3);
    LOGD("[atom format 5] ABC = %d\n", ABC);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(atom_format_6)
{
    unsigned int A, COUNT;

    A = (pkt[0] >> 5) & 0x01;
    COUNT = pkt[0] & 0x1f;
    LOGD("[atom format 6] A = %d, COUNT = %d\n", A, COUNT);

    /* TODO: add trace function */

    return 1;
}

DECL_DECODE_FN(q)
{
    int index = 0, type, IS, count_unknown = 0, i;
    unsigned long long address;
    unsigned char data;
    unsigned int COUNT;

    type = pkt[index++] & 0x0f;
    switch (type) {
    case 0:
    case 1:
    case 2:
        update_address_regs(stream, ADDRESS_REGISTER(stream)[type].address,
                                    ADDRESS_REGISTER(stream)[type].IS);
        break;

    case 5:
    case 6:
        address = ADDRESS_REGISTER(stream)[0].address;
        IS = (type == 5)? ADDR_REG_IS0: ADDR_REG_IS1;
        if (IS == ADDR_REG_IS0) {
            address &= ~0x000001FFLL;
            address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
            if (pkt[1] & c_bit) {
                address &= ~0x0001FE00LL;
                address |= (unsigned long long)pkt[index++] << 9;
            }
        } else {
            address &= ~0x000000FFLL;
            address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
            if (pkt[1] & c_bit) {
                address &= ~0x0000FF00LL;
                address &= (unsigned long long)pkt[index++] << 8;
            }
        }
        update_address_regs(stream, address, IS);
        break;

    case 10:
    case 11:
        address = ADDRESS_REGISTER(stream)[0].address;
        if (type == 10) {
            IS = ADDR_REG_IS0;
            address &= ~0xFFFFFFFFLL;
            address |= (unsigned long long)(pkt[index++] & 0x7F) << 2;
            address |= (unsigned long long)(pkt[index++] & 0x7F) << 9;
            address |= (unsigned long long)pkt[index++] << 16;
            address |= (unsigned long long)pkt[index++] << 24;
        } else {
            IS = ADDR_REG_IS1;
            address &= ~0xFFFFFFFFLL;
            address |= (unsigned long long)(pkt[index++] & 0x7F) << 1;
            address |= (unsigned long long)pkt[index++] << 8;
            address |= (unsigned long long)pkt[index++] << 16;
            address |= (unsigned long long)pkt[index++] << 24;
        }
        update_address_regs(stream, address, IS);
        break;

    case 12:
        break;

    case 15:
        count_unknown = 1;
        break;

    default:
        index = -1;
    }

    if (!count_unknown) {
        COUNT = 0;
        for (i = 0; i < 5; i++) {
            data = pkt[index++];
            COUNT |= (data & ~c_bit) << (7 * i + 3);
            if (!(data & c_bit)) {
                break;
            }
        }
    }

    if (count_unknown) {
        LOGD("[Q] type = %d, address = 0x%016llx, IS = %d, count unknown\n", type,
                ADDRESS_REGISTER(stream)[0].address, ADDRESS_REGISTER(stream)[0].IS);
    } else {
        LOGD("[Q] type = %d, address = 0x%016llx, IS = %d, count =%d\n", type,
                ADDRESS_REGISTER(stream)[0].address, ADDRESS_REGISTER(stream)[0].IS, COUNT);
    }

    /* TODO: add trace function */

    return index;
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
    &PKT_NAME(data_sync_marker),
    &PKT_NAME(commit),
    &PKT_NAME(cancel_format_1),
    &PKT_NAME(cancel_format_2),
    &PKT_NAME(cancel_format_3),
    &PKT_NAME(mispredict),
    &PKT_NAME(cond_inst_format_1),
    &PKT_NAME(cond_inst_format_2),
    &PKT_NAME(cond_inst_format_3),
    &PKT_NAME(cond_flush),
    &PKT_NAME(cond_result_format_1),
    &PKT_NAME(cond_result_format_2),
    &PKT_NAME(cond_result_format_3),
    &PKT_NAME(cond_result_format_4),
    &PKT_NAME(event),
    &PKT_NAME(short_address_is0),
    &PKT_NAME(short_address_is1),
    &PKT_NAME(long_address_32bit_is0),
    &PKT_NAME(long_address_32bit_is1),
    &PKT_NAME(long_address_64bit_is0),
    &PKT_NAME(long_address_64bit_is1),
    &PKT_NAME(exact_match_address),
    &PKT_NAME(context),
    &PKT_NAME(address_context_32bit_is0),
    &PKT_NAME(address_context_32bit_is1),
    &PKT_NAME(address_context_64bit_is0),
    &PKT_NAME(address_context_64bit_is1),
    &PKT_NAME(atom_format_1),
    &PKT_NAME(atom_format_2),
    &PKT_NAME(atom_format_3),
    &PKT_NAME(atom_format_4),
    &PKT_NAME(atom_format_5),
    &PKT_NAME(atom_format_6),
    &PKT_NAME(q),
    NULL,
};

int etmv4_synchronization(struct stream *stream)
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

                    RESET_ADDRESS_REGISTER(stream);

                    return i;
                }
            }
        }
    }

    return -1;
}

void decode_etmv4(void)
{
    tracepkts = etmv4pkts;
    synchronization = etmv4_synchronization;
}
