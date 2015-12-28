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

/*
 * Defines, data structures, declarations for PTM.
 */

enum { NOT_CHANGE = 0, ARM_STATE, THUMB_STATE, THUMBEE_STATE, JAZELLE_STATE };
enum { MAX_NR_ADDR_BIT = 32 };

struct ptm_tracer
{
    unsigned int last_addr;
    int inst_state;
    int cycle_accurate;
    int contextid_size;
};

#define IS_CYC_ACC(t) (((struct ptm_tracer *)(t))->cycle_accurate)
#define CONTEXTID_SIZE(t) (((struct ptm_tracer *)(t))->contextid_size)

extern void tracer_sync(void *t, unsigned int addr,   \
                            int inst_state, unsigned int info,  \
                            unsigned int cyc_cnt, unsigned int contextid);
extern void tracer_branch(void *t, unsigned int addr, int addr_size, \
                            int inst_state, unsigned int exception, int NS, \
                            int Hyp, unsigned int cyc_cnt);
extern void tracer_waypoint(void *t, unsigned int addr, int addr_size,   \
                            int inst_state, int AltS);
extern void tracer_contextid(void *t, unsigned int contextid);
extern void tracer_vmid(void *t, unsigned int VMID);
extern void tracer_timestamp(void *t, unsigned long long timestamp,   \
                            unsigned int cyc_cnt);
extern void tracer_exception_ret(void *t);

/*
 * Defines, data structures, declarations for ETMv4.
 */

enum { ADDR_REG_IS_UNKNOWN = -1, ADDR_REG_IS0 = 0, ADDR_REG_IS1 = 1 };

struct address_register
{
    unsigned long long address;
    int IS;
};

struct etmv4_tracer
{
    unsigned int info;
    unsigned int curr_spec_depth;
    unsigned int cc_threshold;
    struct address_register address_register[3];
};

#define TRACE_INFO(t) (((struct etmv4_tracer *)(t))->info)
#define CURR_SPEC_DEPTH(t) (((struct etmv4_tracer *)(t))->curr_spec_depth)
#define CC_THRESHOLD(t) (((struct etmv4_tracer *)(t))->cc_threshold)
#define ADDRESS_REGISTER(t) ((struct etmv4_tracer *)(t))->address_register
#define RESET_ADDRESS_REGISTER(t)   \
        do {    \
            ((struct etmv4_tracer *)(t))->address_register[0].address = 0;    \
            ((struct etmv4_tracer *)(t))->address_register[0].IS = ADDR_REG_IS_UNKNOWN;   \
            ((struct etmv4_tracer *)(t))->address_register[1].address = 0;    \
            ((struct etmv4_tracer *)(t))->address_register[1].IS = ADDR_REG_IS_UNKNOWN;   \
            ((struct etmv4_tracer *)(t))->address_register[2].address = 0;    \
            ((struct etmv4_tracer *)(t))->address_register[2].IS = ADDR_REG_IS_UNKNOWN;   \
        } while (0)

#endif
