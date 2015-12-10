/*
 * pktproto.h: header of packets
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
#ifndef _PKTPROTO_H
#define _PKTPROTO_H

enum { PKT_TYPE_PTM = 0, PKT_TYPE_ETMV4 };

typedef unsigned char pkt_header;

struct tracepkt
{
    const char *name;
    pkt_header mask;
    pkt_header val;
    int (*decode)(const pkt_header *, struct stream *);
};

#define DECODE_FUNC_NAME(__n) decode_ ## __n

#define DECL_DECODE_FN(__n) \
    static int DECODE_FUNC_NAME(__n)(const unsigned char *pkt, struct stream *stream)

#define PKT_NAME(__n) \
    tracepkt ## __n

#define DEF_TRACEPKT(__n, __m, __v)  \
    DECL_DECODE_FN(__n);    \
    static struct tracepkt PKT_NAME(__n) =   \
    {   \
        .name = # __n,  \
        .mask = (__m),  \
        .val = (__v),   \
        .decode = DECODE_FUNC_NAME(__n),    \
    }

#define TRACEPKT(__n) \
    tracepkt ## __n

typedef int (*sync_func)(struct stream *stream);

extern struct tracepkt **tracepkts;
extern sync_func synchronization;

void decode_etmv4(void);
void decode_ptm(void);

#endif
