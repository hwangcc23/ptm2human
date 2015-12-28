/*
 * etb_format.c: Decode ETB
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "tracer.h"
#include "stream.h"
#include "log.h"
#include "output.h"

#define ETB_PACKET_SIZE 16
#define NULL_TRACE_SOURCE 0

static int init_stream(struct stream *stream, int buff_len, \
            int cycle_accurate, int contextid_size)
{
    if (!stream) {
        LOGE("Invalid stream pointer\n");
        return -1;
    }

    memset(stream, 0, sizeof(struct stream));

    IS_CYC_ACC(&(stream->tracer)) = cycle_accurate;
    CONTEXTID_SIZE(&(stream->tracer)) = contextid_size;
    stream->buff = malloc(buff_len);
    if (!(stream->buff)) {
        LOGE("Fail to allocate memory (%s)\n", strerror(errno));
        return -1;
    }
    memset((void *)stream->buff, 0, stream->buff_len);

    return 0;
}

int decode_etb_stream(struct stream *etb_stream)
{
    struct stream *stream;
    int nr_stream, pkt_idx, byte_idx, id, cur_id, pre_id, nr_new, i, trace_stop = 0;
    unsigned char c, end, tmp;

    if (!etb_stream) {
        LOGE("Invalid stream pointer\n");
        return -1;
    }

    /* create the first stream */
    cur_id = -1;
    pre_id = -1;
    nr_stream = 1;
    stream = malloc(sizeof(struct stream));
    if (!stream) {
        LOGE("Fail to allocate stream (%s)\n", strerror(errno));
        return -1;
    }
    if (init_stream(stream, etb_stream->buff_len,
            IS_CYC_ACC(&(etb_stream->tracer)), CONTEXTID_SIZE(&(etb_stream->tracer)))) {
        return -1;
    }

    for (pkt_idx = 0; pkt_idx < etb_stream->buff_len; pkt_idx += ETB_PACKET_SIZE) {
        if (trace_stop) {
            break;
        }
        end = etb_stream->buff[pkt_idx + ETB_PACKET_SIZE - 1];
        for (byte_idx = 0; byte_idx < (ETB_PACKET_SIZE - 1); byte_idx++) {
            c = etb_stream->buff[pkt_idx + byte_idx];
            if (byte_idx & 1) {
                /* data byte */
                tmp = etb_stream->buff[pkt_idx + byte_idx - 1];
                if ((tmp & 1) &&    /* previous byte is an ID byte */   \
                        end & (1 << (byte_idx / 2))) {
                    /* data corresponds to the previous ID */
                    if (pre_id < 0) {
                        /* drop the byte since there is no ID byte yet */
                        continue;
                    }
                    stream[pre_id].buff[stream[pre_id].buff_len] = c;
                    stream[pre_id].buff_len = stream[pre_id].buff_len + 1;
                } else {
                    /* data corresponds to the new ID */
                    if (cur_id < 0) {
                        /* drop the byte since there is no ID byte yet */
                        continue;
                    }
                    stream[cur_id].buff[stream[cur_id].buff_len] = c;
                    stream[cur_id].buff_len = stream[cur_id].buff_len + 1;
                }
            } else {
                if (c & 1) {
                    /* ID byte */
                    id = (c >> 1) & 0x7f;
                    if (id == NULL_TRACE_SOURCE) {
                        trace_stop = 1;
                        break;
                    } else {
                        pre_id = cur_id;
                        cur_id = id - 1;
                    }

                    if (cur_id >= nr_stream) {
                        /* create new streams */
                        nr_new = cur_id - nr_stream + 1;
                        nr_stream = cur_id + 1;
                        stream = realloc(stream, sizeof(struct stream) * nr_stream);
                        if (!stream) {
                            LOGE("Fail to re-allocate stream (%s)\n", strerror(errno));
                            return -1;
                        }
                        for (i = (nr_stream - nr_new); i < nr_stream; i++) {
                            if (init_stream(&(stream[i]), etb_stream->buff_len, \
                                    IS_CYC_ACC(&(etb_stream->tracer)),   \
                                    CONTEXTID_SIZE(&(etb_stream->tracer)))) {
                                LOGE("Fail to init stream %d\n", i);
                                return -1;
                            }
                        }
                    }
                } else {
                    /* data byte */
                    c |= (end & (1 << (byte_idx / 2)))? 1: 0;
                    if (cur_id < 0) {
                        /* drop the byte since there is no ID byte yet */
                        continue;
                    }
                    stream[cur_id].buff[stream[cur_id].buff_len] = c;
                    stream[cur_id].buff_len = stream[cur_id].buff_len + 1;
                }
            }
        }
    }

    for (i = 0; i < nr_stream; i++) {
        OUTPUT("Decode trace stream of ID %d\n", i);
        LOGD("There are %d bytes in the stream %d\n", stream[i].buff_len, i);
        decode_stream(&(stream[i]));
        free(stream[i].buff);
    }

    free(stream);

    return 0;
}
