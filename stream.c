#include <stdio.h>
#include "log.h"
#include "stream.h"
#include "pftproto.h"

int decode_stream(struct stream *stream)
{
    int cur, i, ret;

    if (!stream) {
        LOGE("Invalid struct stream pointer\n");
        return -1;
    }

    LOGV("Decoding the trace stream...\n");
    for (cur = 0; cur < stream->buff_len; ) {
        char c = stream->buff[cur];

        LOGD("Got a packet header 0x%02x at offset %d\n", c, cur);

        for (i = 0; pftpkts[i]; i++) {
            if ((c & pftpkts[i]->mask) == pftpkts[i]->val) {
                LOGD("Get a packet of type %s\n", pftpkts[i]->name);
                break;
            }
        }
        if (!pftpkts[i]) {
            LOGE("Cannot recognize a packet header 0x%02x\n", c);
            return -1;
        }

        ret = pftpkts[i]->decode(&(stream->buff[cur]), stream);
        if (ret <= 0) {
            LOGE("Cannot decode a packet of type %s at offset %d\n", pftpkts[i]->name, cur);
            return -1;
        } else {
            cur += ret;
        }
    }

    LOGV("Complete decode of the trace stream\n");

    return 0;
}
