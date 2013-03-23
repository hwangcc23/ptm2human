#include "stream.h"
#include "pftproto.h"

DEF_PFTPKT(async, 0xff, 0x00);
DEF_PFTPKT(isync, 0xff, 0x08);
DEF_PFTPKT(atom, 0x81, 0x80);
DEF_PFTPKT(branch_addr, 0x01, 0x01);
DEF_PFTPKT(waypoint_update, 0xff, 0x72);
DEF_PFTPKT(trigger, 0xff, 0x0c);
DEF_PFTPKT(contextid, 0xff, 0x6e);
DEF_PFTPKT(vmid, 0xff, 0x3c);
DEF_PFTPKT(timestamp, 0xfb, 0x42);
DEF_PFTPKT(exception_return, 0xff, 0x76);
DEF_PFTPKT(ignore, 0xff, 0x66);

DECL_DECODE_FN(async)
{
    return 0;
}

DECL_DECODE_FN(isync)
{
    return 0;
}

DECL_DECODE_FN(atom)
{
    return 0;
}

DECL_DECODE_FN(branch_addr)
{
    return 0;
}

DECL_DECODE_FN(waypoint_update)
{
    return 0;
}

DECL_DECODE_FN(trigger)
{
    return 0;
}

DECL_DECODE_FN(contextid)
{
    return 0;
}

DECL_DECODE_FN(vmid)
{
    return 0;
}

DECL_DECODE_FN(timestamp)
{
    return 0;
}

DECL_DECODE_FN(exception_return)
{
    return 0;
}

DECL_DECODE_FN(ignore)
{
    return 0;
}

struct pftpkt *pftpkts[] =
{
    &PKT_NAME(async),
    &PKT_NAME(isync),
    &PKT_NAME(atom),
    &PKT_NAME(branch_addr),
    &PKT_NAME(waypoint_update),
    &PKT_NAME(trigger),
    &PKT_NAME(contextid),
    &PKT_NAME(vmid),
    &PKT_NAME(timestamp),
    &PKT_NAME(exception_return),
    &PKT_NAME(ignore),
};
