#ifndef _PKTPROTO_H
#define _PKTPROTO_H

enum { PKT_TYPE_PFT = 0, PKT_TYPE_ETMV4 };

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

void use_etmv4(void);
void use_pft(void);

#endif
