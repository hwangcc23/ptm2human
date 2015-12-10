/*
 * stream.h: header of trace stream
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
#ifndef _STREAM_H
#define _STREAM_H

enum
{
    READING = 0,
    SYNCING,
    INSYNC,
    DECODING,
    DECODED,
};

struct ptm_stream_info
{
    int cycle_accurate;
    int contextid_size;
};

enum { ADDR_REG_IS_UNKNOWN = -1, ADDR_REG_IS0 = 0, ADDR_REG_IS1 = 1 };

struct address_register
{
    unsigned long long address;
    int IS;
};

struct etmv4_stream_info
{
    unsigned int info;
    unsigned int curr_spec_depth;
    unsigned int cc_threshold;
    struct address_register address_register[3];
};

struct stream
{
    char *buff;
    unsigned int buff_len;
    int state;
    union
    {
        struct ptm_stream_info ptm;
        struct etmv4_stream_info etmv4;
    } info;
    struct tracer tracer;
};

#define IS_CYC_ACC_STREAM(s) ((s)->info.ptm.cycle_accurate)
#define CONTEXTID_SIZE(s) ((s)->info.ptm.contextid_size)

#define TRACE_INFO(s) ((s)->info.etmv4.info)
#define CURR_SPEC_DEPTH(s) ((s)->info.etmv4.curr_spec_depth)
#define CC_THRESHOLD(s) ((s)->info.etmv4.cc_threshold)
#define ADDRESS_REGISTER(s) (s)->info.etmv4.address_register
#define RESET_ADDRESS_REGISTER(s)   \
        do {    \
            (s)->info.etmv4.address_register[0].address = 0;    \
            (s)->info.etmv4.address_register[0].IS = ADDR_REG_IS_UNKNOWN;   \
            (s)->info.etmv4.address_register[1].address = 0;    \
            (s)->info.etmv4.address_register[1].IS = ADDR_REG_IS_UNKNOWN;   \
            (s)->info.etmv4.address_register[2].address = 0;    \
            (s)->info.etmv4.address_register[2].IS = ADDR_REG_IS_UNKNOWN;   \
        } while (0)

extern int decode_stream(struct stream *stream);
extern int decode_etb_stream(struct stream *stream);

#endif
