/*
 * tracer.h: header of ETMv4 tracer
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
#ifndef _TRACER_ETMV4_H
#define _TRACER_ETMV4_H

enum { ADDR_REG_IS_UNKNOWN = -1, ADDR_REG_IS0 = 0, ADDR_REG_IS1 = 1 };

enum { ATOM_TYPE_E = 1, ATOM_TYPE_N = 2 };

struct address_register
{
    unsigned long long address;
    int IS;
};

struct etmv4_tracer
{
    unsigned int info;
    unsigned long long timestamp;
    struct address_register address_register[3];
    unsigned int context_id;
    unsigned int vmid:8;
    unsigned int ex_level:2;
    unsigned int security:1;
    unsigned int sixty_four_bit:1;
    unsigned int curr_spec_depth;
    unsigned int p0_key;
    unsigned int cond_c_key;
    unsigned int cond_r_key;
    unsigned int cond_key_max_incr;
    unsigned int max_spec_depth;
    unsigned int cc_threshold;
};

#define TRACE_INFO(t) (((struct etmv4_tracer *)(t))->info)
#define TRACE_TIMESTAMP(t) (((struct etmv4_tracer *)(t))->timestamp)
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
#define CONTEXT_ID(t) (((struct etmv4_tracer *)(t))->context_id)
#define VMID(t) (((struct etmv4_tracer *)(t))->vmid)
#define EX_LEVEL(t) (((struct etmv4_tracer *)(t))->ex_level)
#define SECURITY(t) (((struct etmv4_tracer *)(t))->security)
#define SIXTY_FOUR_BIT(t) (((struct etmv4_tracer *)(t))->sixty_four_bit)
#define CURR_SPEC_DEPTH(t) (((struct etmv4_tracer *)(t))->curr_spec_depth)
#define P0_KEY(t) (((struct etmv4_tracer *)(t))->p0_key)
#define COND_C_KEY(t) (((struct etmv4_tracer *)(t))->cond_c_key)
#define COND_R_KEY(t) (((struct etmv4_tracer *)(t))->cond_r_key)
#define COND_KEY_MAX_INCR(t) (((struct etmv4_tracer *)(t))->cond_key_max_incr)
#define MAX_SPEC_DEPTH(t) (((struct etmv4_tracer *)(t))->max_spec_depth)
#define CC_THRESHOLD(t) (((struct etmv4_tracer *)(t))->cc_threshold)


extern void tracer_trace_info(void *t, unsigned int plctl, unsigned int info,\
                              unsigned int key, unsigned int spec,\
                              unsigned int cyct);
extern void tracer_trace_on(void *t);
extern void tracer_discard(void *t);
extern void tracer_overflow(void *t);
extern void tracer_ts(void *t, unsigned long long timestamp, int have_cc, unsigned int count,\
                      int nr_replace);
extern void tracer_exception(void *t, int type);
extern void tracer_exception_return(void *t);
extern void tracer_cc(void *t, int unknown, unsigned int count);
extern void tracer_commit(void *t, unsigned int commit);
extern void tracer_cancel(void *t, int mispredict, unsigned int cancel);
extern void tracer_mispredict(void *t, int arg);
extern void tracer_cond_inst(void *t, int format, unsigned int param1, unsigned int param2);
extern void tracer_context(void *t, int p, int el, int sf, int ns, \
                           int v, unsigned int vmid,   \
                           int c, unsigned int contextid);
extern void tracer_address(void *t);
extern void tracer_atom(void *t, int type);
extern void tracer_q(void *t, unsigned int count);

#endif
