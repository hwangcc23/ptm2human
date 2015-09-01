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

struct pft_stream_info
{
    int cycle_accurate;
    int contextid_size;
};

struct etmv4_stream_info
{
    unsigned int info;
    unsigned int curr_spec_depth;
    unsigned int cc_threshold;
};

struct stream
{
    char *buff;
    unsigned int buff_len;
    int state;
    union
    {
        struct pft_stream_info pft;
        struct etmv4_stream_info etmv4;
    } info;
    struct tracer tracer;
};

#define IS_CYC_ACC_STREAM(s) ((s)->info.pft.cycle_accurate)
#define CONTEXTID_SIZE(s) ((s)->info.pft.contextid_size)
#define TRACE_INFO(s) ((s)->info.etmv4.info)
#define CURR_SPEC_DEPTH(s) ((s)->info.etmv4.curr_spec_depth)
#define CC_THRESHOLD(s) ((s)->info.etmv4.cc_threshold)

extern int decode_stream(struct stream *stream);
extern int decode_etb_stream(struct stream *stream);

#endif
