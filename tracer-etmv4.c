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

void tracer_trace_info(void *t, unsigned int plctl, unsigned int info,\
                       unsigned int key, unsigned int spec, unsigned int cyct)
{
    struct etmv4_tracer *tracer = (struct etmv4_tracer *)t;

    RESET_ADDRESS_REGISTER(tracer);

    TRACE_INFO(tracer) = (plctl & 1)? info: 0;
    P0_KEY(tracer) = (plctl & 2)? key: 0;
    CURR_SPEC_DEPTH(tracer) = (plctl & 4)? spec: 0;
    CC_THRESHOLD(tracer) = (plctl & 8)? cyct: 0;

    OUTPUT("TraceInfo - %s, %s, %s, %s, p0_key = 0x%X, curr_spec_depth = %d, cc_threshold = 0x%X)\n",
            (TRACE_INFO(tracer) & 0x01)? "Cycle count enabled": "Cycle count disabled",
            (TRACE_INFO(tracer) & 0x0E)? "Tracing of conditional non-branch instruction enabled": "Tracing of conditional non-branch instruction disabled",
            (TRACE_INFO(tracer) & 0x10)? "Explicit tracing of load instructions": "No explicit tracing of load instructions",
            (TRACE_INFO(tracer) & 0x20)? "Explicit tracing of store instructions": "No explicit tracing of store instructions",
            P0_KEY(tracer), CURR_SPEC_DEPTH(tracer), CC_THRESHOLD(tracer));
}
