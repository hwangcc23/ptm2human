#ifndef _STREAM_H
#define _STREAM_H

struct stream
{
    const char *buff;
    unsigned int buff_len;
    int cycle_accurate;
    int contextid_size;
};

extern int decode_stream(struct stream *stream);

#endif
