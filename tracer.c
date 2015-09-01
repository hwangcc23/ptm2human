#include <stdio.h>
#include <sys/types.h>
#include "tracer.h"
#include "stream.h"
#include "output.h"

/*
 * stream_of_tracer: cast the tracer member of a stream structure out to the stream struct
 */
#define stream_of_tracer(_t)    \
    (struct stream *)((ssize_t)(_t) - (ssize_t)&(((struct stream *)0x00)->tracer))

void tracer_sync(struct tracer *tracer, unsigned int addr, int inst_state, unsigned int info,   \
                    unsigned int cyc_cnt, unsigned int contextid)
{
    tracer->last_addr = addr;
    if (inst_state == THUMB_STATE) {
        tracer->inst_state = (info & 0x04)? THUMBEE_STATE: THUMB_STATE;
    } else {
        tracer->inst_state = ARM_STATE;
    }
    tracer->inst_state = inst_state;

    OUTPUT("instruction addr at 0x%x, ", tracer->last_addr);
    switch (tracer->inst_state) {
    case ARM_STATE:
        OUTPUT("ARM state, ");
        break;
    case THUMB_STATE:
        OUTPUT("Thumb state, ");
        break;
    case THUMBEE_STATE:
        OUTPUT("ThumbEE state, ");
        break;
    case JAZELLE_STATE:
        OUTPUT("Jazelle state, ");
        break;
    default:
        break;
    }
    OUTPUT("%s, ", (info & 0x08)? "non-secure state": "secure state");

    if (IS_CYC_ACC_STREAM(stream_of_tracer(tracer))) {
        OUTPUT("cycle count 0x%08x, ", cyc_cnt);
    }
    if (CONTEXTID_SIZE(stream_of_tracer(tracer))) {
        OUTPUT("context ID 0x%x, ", contextid);
    }
    OUTPUT("\n"); 
}

void tracer_branch(struct tracer *tracer, unsigned int addr, int addr_size, \
                    int inst_state, unsigned int exception, int NS, int Hyp, unsigned int cyc_cnt)
{
    if (addr_size != MAX_NR_ADDR_BIT) {
        if (tracer->inst_state == ARM_STATE) {
            addr *= 4;
            addr_size += 2;
        } else if (tracer->inst_state == THUMB_STATE) {
            addr *= 2;
            addr_size += 1;
        }
        tracer->last_addr &= ~((1 << addr_size) - 1);
        tracer->last_addr |= addr;
    } else {
        tracer->last_addr = addr;
    }
    if (inst_state > NOT_CHANGE) {
        tracer->inst_state = inst_state;
    }

    OUTPUT("instruction addr at 0x%x, ", tracer->last_addr);
    switch (tracer->inst_state) {
    case ARM_STATE:
        OUTPUT("ARM state, ");
        break;
    case THUMB_STATE:
        OUTPUT("Thumb state, ");
        break;
    case THUMBEE_STATE:
        OUTPUT("ThumbEE state, ");
        break;
    case JAZELLE_STATE:
        OUTPUT("Jazelle state, ");
        break;
    default:
        break;
    }
    if (exception) {
        OUTPUT("exception (");
        switch (exception) {
        case 1:
            OUTPUT("Entered Debug state when Halting debug-mode is enabled");
            break;
        case 2:
            OUTPUT("Secure Monitor Call");
            break;
        case 3:
            OUTPUT("entry to Hyp mode");
            break;
        case 4:
            OUTPUT("Asynchronous Data Abort");
            break;
        case 5:
            OUTPUT("ThumbEE check fail");
            break;
        case 8:
            OUTPUT("Porcessor Reset");
            break;
        case 9:
            OUTPUT("Undefined Instruction");
            break;
        case 10:
            OUTPUT("Supervisor Call");
            break;
        case 11:
            OUTPUT("Prefetch Abort or software breakpoint");
            break;
        case 12:
            OUTPUT("Synchronous Data Abort or software watchpoint");
            break;
        case 13:
            OUTPUT("Generic exception");
            break;
        case 14:
            OUTPUT("IRQ");
            break;
        case 15:
            OUTPUT("FIQ");
            break;
        default:
            OUTPUT("reserved");
            break;
        }
        OUTPUT("), ");
        OUTPUT("%s, ", NS? "non-secure state": "secure state");
        if (Hyp) {
            OUTPUT("into Hyp mode, ");
        }
    }
    if (IS_CYC_ACC_STREAM(stream_of_tracer(tracer))) {
        OUTPUT("cycle count 0x%08x, ", cyc_cnt);
    }
    OUTPUT("\n");
}

void tracer_waypoint(struct tracer *tracer, unsigned int addr, int addr_size,   \
                        int inst_state, int AltS)
{
    if (addr_size != MAX_NR_ADDR_BIT) {
        if (tracer->inst_state == ARM_STATE) {
            addr *= 4;
            addr_size += 2;
        } else if (tracer->inst_state == THUMB_STATE) {
            addr *= 2;
            addr_size += 1;
        }
        tracer->last_addr &= ~((1 << addr_size) - 1);
        tracer->last_addr |= addr;
    } else {
        tracer->last_addr = addr;
    }
    if (inst_state > NOT_CHANGE) {
        tracer->inst_state = inst_state;
    }

    OUTPUT("instruction addr at 0x%x, ", tracer->last_addr);
    if (AltS != -1) {
        OUTPUT("AltS = %d, ", AltS);
    }
    OUTPUT("\n");
}

void tracer_contextid(struct tracer *tracer, unsigned int contextid)
{
    OUTPUT("context ID sets to 0x%x\n", contextid);
}

void tracer_vmid(struct tracer *tracer, unsigned int VMID)
{
    OUTPUT("VMID sets to 0x%x\n", VMID);
}

void tracer_timestamp(struct tracer *tracer, unsigned long long timestamp, unsigned int cyc_cnt)
{
    OUTPUT("timestamp 0x%llx, ", timestamp);
    if (IS_CYC_ACC_STREAM(stream_of_tracer(tracer))) {
        OUTPUT("cycle count 0x%08x, ", cyc_cnt);
    }
    OUTPUT("\n");
}

void tracer_exception_ret(struct tracer *tracer)
{
    OUTPUT("exception return\n");
}
