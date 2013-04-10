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

struct stream
{
    char *buff;
    unsigned int buff_len;
    int cycle_accurate;
    int contextid_size;
    int state;
};

extern int decode_stream(struct stream *stream);
extern int decode_etb_stream(struct stream *stream);

#endif
