/*
 * tracer.h: header of trace analyzer
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
#ifndef _TRACER_H
#define _TRACER_H

enum { NOT_CHANGE = 0, ARM_STATE, THUMB_STATE, THUMBEE_STATE, JAZELLE_STATE };
enum { MAX_NR_ADDR_BIT = 32 };

struct tracer
{
    unsigned int last_addr;
    int inst_state;
};

extern void tracer_sync(struct tracer *tracer, unsigned int addr,   \
                            int inst_state, unsigned int info,  \
                            unsigned int cyc_cnt, unsigned int contextid);
extern void tracer_branch(struct tracer *tracer, unsigned int addr, int addr_size, \
                            int inst_state, unsigned int exception, int NS, \
                            int Hyp, unsigned int cyc_cnt);
extern void tracer_waypoint(struct tracer *tracer, unsigned int addr, int addr_size,   \
                            int inst_state, int AltS);
extern void tracer_contextid(struct tracer *tracer, unsigned int contextid);
extern void tracer_vmid(struct tracer *tracer, unsigned int VMID);
extern void tracer_timestamp(struct tracer *tracer, unsigned long long timestamp,   \
                            unsigned int cyc_cnt);
extern void tracer_exception_ret(struct tracer *tracer);

#endif
