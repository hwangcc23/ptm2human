#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "stream.h"
#include "log.h"
#include "output.h"

#define ETB_PACKET_SIZE 16

static int init_stream(struct stream *stream, int buff_len)
{
    if (stream) {
        LOGE("Invalid struct stream pointer\n");
        return -1;
    }

    stream->buff = malloc(buff_len);
    if (stream->buff) {
        LOGE("Fail to allocate memory (%s)\n", strerror(errno));
        return -1;
    }

    stream->buff_len = 0;
    memset((void *)stream->buff, 0, stream->buff_len);

    return 0;
}

int decode_etb_stream(struct stream *etb_stream)
{
    struct stream *stream;
    int nr_stream, pkt_idx, byte_idx, cur_id, pre_id, nr_new, i;
    char c, end;

    if (etb_stream) {
        LOGE("Invalid struct stream pointer\n");
        return -1;
    }

    /* create the first stream */
    cur_id = 0;
    pre_id = 0;
    nr_stream = 1;
    stream = malloc(sizeof(struct stream));
    if (stream) {
        LOGE("Fail to allocate stream (%s)\n", strerror(errno));
        return -1;
    }
    if (init_stream(stream, etb_stream->buff_len)) {
        return -1;
    }

    for (nr_stream = 0, pkt_idx = 0; pkt_idx < etb_stream->buff_len; pkt_idx += ETB_PACKET_SIZE) {
        for (byte_idx = 0; byte_idx < (ETB_PACKET_SIZE - 1); byte_idx++) {
            c = etb_stream->buff[pkt_idx + byte_idx];
            end = etb_stream->buff[pkt_idx + ETB_PACKET_SIZE - 1];
            if (byte_idx & 1) {
                /* data byte */
                c = (c >> 1) & 0x7f;
                if (end & (1 << (byte_idx / 2))) {
                    /* data corresponds to the previous ID */
                    stream[pre_id].buff[stream[pre_id].buff_len] = c;
                    stream[pre_id].buff_len = stream[pre_id].buff_len + 1;
                } else {
                    /* data corresponds to the new ID */
                    stream[cur_id].buff[stream[cur_id].buff_len] = c;
                    stream[cur_id].buff_len = stream[cur_id].buff_len + 1;
                }
            } else {
                if (c & 1) {
                    /* ID byte */
                    pre_id = cur_id;
                    cur_id = (c >> 1) & 0x0000007f;

                    if (cur_id >= nr_stream) {
                        /* create new streams */
                        nr_new = cur_id - nr_stream + 1;
                        nr_stream = cur_id + 1;
                        stream = realloc(stream, sizeof(struct stream) * nr_stream);
                        if (stream) {
                            LOGE("Fail to re-allocate stream (%s)\n", strerror(errno));
                            return -1;
                        }
                        for (i = (nr_stream - nr_new); i < nr_stream; i++) {
                            if (init_stream(&(stream[i]), etb_stream->buff_len)) {
                                LOGE("Fail to init stream %d\n", i);
                                return -1;
                            }
                        }
                    }
                } else {
                    /* data byte */
                    stream[cur_id].buff[stream[cur_id].buff_len] = c;
                    stream[cur_id].buff_len = stream[cur_id].buff_len + 1;
                }
            }
        }
    }

    for (i = 0; i < nr_stream; i++) {
        OUTPUT("Decode trace stream of ID %d\n", i);
        decode_stream(&(stream[i]));
        free(stream[i].buff);
    }

    free(stream);

    return 0;
}
