/*
 * ptm2human.c: Entry
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
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"

int debuglog_on = 0;

static const struct option options[] = 
{
    { "input", 1, 0, 'i' },
    { "context", 1, 0, 'c' },
    { "cycle-accurate", 0, 0, 'C' },
    { "decode-ptm", 0, 0, 'p' },
    { "trcidr0", 1, 0, '0' },
    { "trcidr8", 1, 0, '8' },
    { "trcidr9", 1, 0, '9' },
    { "trcidr12", 1, 0, '2' },
    { "trcidr13", 1, 0, '3' },
    { "decode-etmv4", 0, 0, 'e' },
    { "debuglog", 0, 0, 'd' },
    { "help", 0, 0, 'h' },
    { NULL, 0, 0, 0   },
};

static const char *optstring = "i:c:Cp0:8:9:2:3:edh";

void usage(void)
{
    printf("Usage: ptm2human [options] -i /TRACE/FILE/PATH\n");
    printf("Options:\n");
    printf("  -i|--input <trace file>                 Give the trace file\n\n");
    printf("  -p|--decode-ptm (default option)        Decode PTM trace\n");
    printf("  -c|--context <context ID size>          Give the size of ContextID for PTM trace only\n");
    printf("  -C|--cycle-accurate                     Enable Cycle-Accurate for PTM trace only\n\n");
    printf("  -e|--decode-etmv4                       Decode ETMv4 trace\n");
    printf("  -0|--trcidr0 <TRCIDR0 value>            Give the value of TRCIDR0 which indicates conditional tracing type\n");
    printf("  -8|--trcidr8 <TRCIDR8 value>            Give the value of TRCIDR8 which indicates max speculation depth\n");
    printf("  -9|--trcidr9 <TRCIDR9 value>            Give the value of TRCIDR9 which indicates the number of P0 right-hand keys\n");
    printf("  -2|--trcidr12 <TRCIDR12 value>          Give the value of TRCIDR12 which indicates the number of right-hand keys for cond-inst elements\n");
    printf("  -3|--trcidr13 <TRCIDR13 value>          Give the value of TRCIDR13 which indicates the number of special right-hand keys for cond-inst elements\n\n");
    printf("  -d|--debuglog                           Enable debug messages\n");
    printf("  -h|--help                               Show help messages\n");
}

int file2buff(const char *input_file, const char *buff, unsigned int buff_len)
{
    int fd;

    if (!input_file) {
        LOGE("Invalid input_file\n");
        return -1;
    }
    if (!buff) {
        LOGE("Invalid buff\n");
        return -1;
    }

    fd = open(input_file, O_RDONLY);
    if (fd == -1) {
        LOGE("Fail to open %s (%s)\n", input_file, strerror(errno));
        return -1;
    }

    LOGV("Reading %s\n", input_file);
    if (read(fd, (void *)buff, buff_len) != buff_len) {
        LOGE("Fail to read %s (%s)\n", input_file, strerror(errno));
        return -1;
    }

    close(fd);

    return 0;
}

int main(int argc, char **argv)
{
    int longindex, c, ret, pkttype = -1;
    unsigned int trcidr12 = 0, trcidr13 = 0;
    const char *input_file = NULL;
    struct stream stream;
    struct stat sb;

    /* disable output buffering */
    setbuf(stdout, NULL);

    memset(&stream, 0, sizeof(struct stream));

    for (;;) {
        c = getopt_long(argc, argv, optstring, options, &longindex);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'i':
            input_file = strdup(optarg);
            break;

        case 'c':
            CONTEXTID_SIZE(&(stream.tracer)) = atoi(optarg);
            break;

        case 'C':
            IS_CYC_ACC(&(stream.tracer)) = 1;
            break;

        case 'p':
            if (pkttype == -1) {
                pkttype = PKT_TYPE_PTM;
                decode_ptm();
            } else {
                LOGE("Use either --decode_ptm or --decode_etmv4\n");
                return EXIT_FAILURE;
            }
            break;

        case 'e':
            if (pkttype == -1) {
                pkttype = PKT_TYPE_ETMV4;
                decode_etmv4();
            } else {
                LOGE("Use either --decode_ptm or --decode_etmv4\n");
                return EXIT_FAILURE;
            }
            break;

        case '0':
            CONDTYPE(&(stream.tracer)) = (atoi(optarg) & 0x00003000) >> 12;
            break;

        case '8':
            MAX_SPEC_DEPTH(&(stream.tracer)) = atoi(optarg);
            break;

        case '9':
            P0_KEY_MAX(&(stream.tracer)) = atoi(optarg);
            break;

        case '2':
            trcidr12 = atoi(optarg);
            break;

        case '3':
            trcidr13 = atoi(optarg);
            break;

        case 'd':
            debuglog_on = 1;
            break;

        case 'h':
            usage();
            return EXIT_SUCCESS;
            break;

        default:
            LOGE("Unknown argument: %c\n", c);
            break;
        }
    }

    if (argc != optind || !input_file) {
        LOGE("Invalid arguments or no input file\n");
        usage();
        return EXIT_FAILURE;
    }

    if (pkttype == -1) {
        pkttype = PKT_TYPE_PTM;
        decode_ptm();
    }

    /* validate context ID size */
    switch (CONTEXTID_SIZE(&(stream.tracer))) {
    case 0:
    case 1:
    case 2:
    case 4:
        break;
    default:
        LOGE("Invalid context ID size %d\n", CONTEXTID_SIZE(&(stream.tracer)));
        return EXIT_FAILURE;
        break;
    }

    /* validate CONDTYPE in trcidr0 */
    if (CONDTYPE(&(stream.tracer)) > 2) {
        LOGE("Invalid CONDTYPE in TRCIDR0: %d (should be either 0 or 1)\n", CONDTYPE(&(stream.tracer)));
        return EXIT_FAILURE;
    }

    /* validate trcidr12 and trcidr13 */
    if (trcidr12 < trcidr13) {
        LOGE("Invalid TRCIDR12/TRCIDR13: TRCIDR12 (%d) < TRCIDR13 (%d)\n", trcidr12, trcidr13);
        return EXIT_FAILURE;
    } else {
        COND_KEY_MAX_INCR(&(stream.tracer)) = trcidr12 - trcidr13;
    }

    ret = stat(input_file, &sb);
    if (ret == -1) {
        LOGE("Cannot stat %s (%s)\n", input_file, strerror(errno));
        return EXIT_FAILURE;
    }

    stream.buff_len = sb.st_size;
    stream.buff = malloc(stream.buff_len);
    if (!(stream.buff)) {
        LOGE("Fail to allocate memory (%s)\n", strerror(errno));
        return EXIT_FAILURE;
    }
    memset((void *)stream.buff, 0, stream.buff_len);

    file2buff(input_file, stream.buff, stream.buff_len);

    ret = decode_etb_stream(&stream);

    free((void *)stream.buff);

    if (ret) {
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}
