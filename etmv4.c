#include <stdio.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"
#include "config.h"

#if TRACE_STREAM_PROT == ETMV4_TRACE_STREAM

DEF_TRACEPKT(async, 0xff, 0x00);

DECL_DECODE_FN(async)
{
    int index;

    index = -1;

    return index;
}

struct tracepkt *etmv4pkts[] =
{
    &PKT_NAME(async),
    NULL,
};

struct tracepkt **tracepkts = etmv4pkts;

int synchronization(struct stream *stream)
{
    int i, p;
    unsigned char c;

    for (i = 0; i < stream->buff_len; i++) {
        c = stream->buff[i];
        if ((c & PKT_NAME(async).mask) == PKT_NAME(async).val) {
            p = DECODE_FUNC_NAME(async)((const unsigned char *)&(stream->buff[i]), stream);
            if (p > 0) {
                /* SYNCING -> INSYNC */
                stream->state++;
                return i;
            }
        }
    }

    return -1;
}

#endif
