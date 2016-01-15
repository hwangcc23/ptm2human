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

struct address_register
{
    unsigned long long address;
    int IS;
};

struct etmv4_tracer
{
    unsigned int info;
    unsigned int p0_key;
    unsigned int curr_spec_depth;
    unsigned int cc_threshold;
    struct address_register address_register[3];
};

#define TRACE_INFO(t) (((struct etmv4_tracer *)(t))->info)
#define P0_KEY(t) (((struct etmv4_tracer *)(t))->p0_key)
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


extern void tracer_trace_info(void *t, unsigned int plctl, unsigned int info,\
                              unsigned int key, unsigned int spec,\
                              unsigned int cyct);
extern void tracer_trace_on(void *t);

#endif
