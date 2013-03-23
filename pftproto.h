#ifndef _PFTPROTO_H
#define _PFTPROTO_H

typedef unsigned char pkt_header;

struct pftpkt 
{
    const char *name;
    pkt_header mask;
    pkt_header val;
    int (*decode)(const pkt_header *, struct stream *);
};

#define DECODE_FUNC_NAME(__n) decode_ ## __n
#define DECL_DECODE_FN(__n) \
    static int DECODE_FUNC_NAME(__n)(const pkt_header *pkt, struct stream *s)

#define PKT_NAME(__n) \
    pftpkt ## __n

#define DEF_PFTPKT(__n, __m, __v)  \
    DECL_DECODE_FN(__n);    \
    struct pftpkt PKT_NAME(__n) =   \
    {   \
        .name = # __n,  \
        .mask = (__m),  \
        .val = (__v),   \
        .decode = DECODE_FUNC_NAME(__n),    \
    }

#define PFTPKT(__n) \
    pftpkt ## __n

#endif
