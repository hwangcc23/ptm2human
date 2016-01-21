/*
 * tracer-etmv4.c: Core of ETMv4 tracer
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <stdio.h>
#include "tracer.h"
#include "stream.h"
#include "output.h"
#include "log.h"

void tracer_trace_info(void *t, unsigned int plctl, unsigned int info,\
                       unsigned int key, unsigned int spec, unsigned int cyct)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    RESET_ADDRESS_REGISTER(tracer);

    TRACE_INFO(tracer) = (plctl & 1)? info: 0;
    P0_KEY(tracer) = (plctl & 2)? key: 0;
    CURR_SPEC_DEPTH(tracer) = (plctl & 4)? spec: 0;
    CC_THRESHOLD(tracer) = (plctl & 8)? cyct: 0;

    OUTPUT("TraceInfo - %s,\n", (TRACE_INFO(tracer) & 0x01)? "Cycle count enabled": "Cycle count disabled");
    OUTPUT("            %s,\n", (TRACE_INFO(tracer) & 0x0E)? "Tracing of conditional non-branch instruction enabled": "Tracing of conditional non-branch instruction disabled");
    OUTPUT("            %s,\n", (TRACE_INFO(tracer) & 0x10)? "Explicit tracing of load instructions": "No explicit tracing of load instructions");
    OUTPUT("            %s,\n", (TRACE_INFO(tracer) & 0x20)? "Explicit tracing of store instructions": "No explicit tracing of store instructions");
    OUTPUT("            p0_key = 0x%X,\n", P0_KEY(tracer));
    OUTPUT("            curr_spec_depth = %d,\n", CURR_SPEC_DEPTH(tracer));
    OUTPUT("            cc_threshold = 0x%X\n", CC_THRESHOLD(tracer));
}

void tracer_trace_on(void *t)
{
    OUTPUT("TraceOn - A discontinuity in the trace stream\n");
}

void tracer_ts(void *t, unsigned long long timestamp, int have_cc, unsigned int count)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;
    int clz, i;

    if (!timestamp) {
        clz = __builtin_clz(timestamp);

        LOGD("before-replace: TRACE_TIMESTAMP = 0x%016llx, timestamp = 0x%016llx, clz = %d\n",
             TRACE_TIMESTAMP(tracer), timestamp, clz);

        for (i = 0; i < (64 - clz); i++) {
            TRACE_TIMESTAMP(tracer) &= ~(0x1LL) << i;
        }
        TRACE_TIMESTAMP(tracer) |= timestamp;

        LOGD("after-replace: TRACE_TIMESTAMP = 0x%016llx\n", TRACE_TIMESTAMP(tracer));
    }

    OUTPUT("Timestamp - %lld\n", TRACE_TIMESTAMP(tracer));
    if (have_cc) {
        OUTPUT("            (number of cycles between the most recent Cycle Count element %d)\n", count);
    }
}

void tracer_commit(void *t, unsigned int commit)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    OUTPUT("Commit - %d\n", commit);

    CURR_SPEC_DEPTH(tracer) -= commit;
}

void tracer_cancel(void *t, int mispredict, unsigned int cancel)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    OUTPUT("Cancel - %d\n", cancel);

    CURR_SPEC_DEPTH(tracer) -= cancel;

    /* TODO: p0_key = (p0_key -cancel ) % p0_max_key */

    if (mispredict) {
        /* TODO: emit mispredict */
        /* TODO: emit conditional_flush */
    }
}

void tracer_context(void *t, int p, int el, int sf, int ns, \
                    int v, unsigned int vmid,   \
                    int c, unsigned int contextid)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    if (p) {
        EX_LEVEL(tracer) = el;
        SIXTY_FOUR_BIT(tracer) = sf;
        SECURITY(tracer) = !ns;
        if (v) {
            VMID(tracer) = vmid;
        }
        if (c) {
            CONTEXT_ID(tracer) = contextid;
        }
    }

    OUTPUT("Context - Context ID = 0x%X,\n", CONTEXT_ID(tracer));
    OUTPUT("          VMID = 0x%X,\n", VMID(tracer));
    OUTPUT("          Exception level = EL%d,\n", EX_LEVEL(tracer));
    OUTPUT("          Security = %s,\n", (SECURITY(tracer))? "S": "NS");
    OUTPUT("          %d-bit instruction\n", (SIXTY_FOUR_BIT(tracer))? 64: 32);
}

void tracer_address(void *t)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;
    unsigned long long address = ADDRESS_REGISTER(tracer)[0].address;
    int IS = ADDRESS_REGISTER(tracer)[0].IS;

    if (SIXTY_FOUR_BIT(tracer)) {
        OUTPUT("Address - Instruction address 0x%016llx, Instruction set Aarch64\n", address);
    } else {
        if (IS) {
            OUTPUT("Address - Instruction address 0x%016llx, Instruction set Aarch32 (ARM)\n", address);
        } else {
            OUTPUT("Address - Instruction address 0x%016llx, Instruction set Aarch32 (Thumb)\n", address);
        }
    }
}

void tracer_atom(void *t, int type)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    if (type == ATOM_TYPE_E) {
        OUTPUT("ATOM - E\n");
    } else if (type == ATOM_TYPE_N) {
        OUTPUT("ATOM - N\n");
    } else {
        LOGE("Invalid ATOM type (%d)\n", type);
        return ;
    }

    /* TODO: p0_key = (p0_key + 1) % p0_max_key */

    CURR_SPEC_DEPTH(tracer)++;
    /* TODO: initialize MAX_SPEC_DEPTH */
    if (CURR_SPEC_DEPTH(tracer) > MAX_SPEC_DEPTH(tracer)) {
        tracer_commit(tracer, 1);
    }
}

void tracer_q(void *t, unsigned int count)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    if (count) {
        OUTPUT("Q - %d of instructions\n", count);
    } else {
        OUTPUT("Q - UNKNOWN of instructions\n");
    }

    /* TODO: p0_key = (p0_key + 1) % p0_max_key */

    CURR_SPEC_DEPTH(tracer)++;
    /* TODO: initialize MAX_SPEC_DEPTH */
    if (CURR_SPEC_DEPTH(tracer) > MAX_SPEC_DEPTH(tracer)) {
        tracer_commit(tracer, 1);
    }
}
