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

static const struct option options[] = 
{
    { "input", 1, 0, 'i' },
    { "context", 1, 0, 'c' },
    { "cycle-accurate", 0, 0, 'C' },
    { "decode-ptm", 0, 0, 'p' },
    { "decode-etmv4", 0, 0, 'e' },
    { "help", 0, 0, 'h' },
    { NULL, 0, 0, 0   },
};

static const char *optstring = "i:c:Cpeh";

void usage(void)
{
    LOGV("Usage: ptm2human [options]\n");
    LOGV("Options:\n");
    LOGV("  -i|--input <PTM data stream file>\n");
    LOGV("  -c|--context <context ID size>\n");
    LOGV("  -C|--cycle-accurate\n");
    LOGV("  -p|--decode-ptm (default option)\n");
    LOGV("  -e|--decode-etmv4\n");
    LOGV("  -h|--help\n");
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
    const char *input_file = NULL;
    struct stream stream;
    struct stat sb;

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
            CONTEXTID_SIZE(&stream) = atoi(optarg);
            break;

        case 'C':
            IS_CYC_ACC_STREAM(&stream) = 1;
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
    switch (CONTEXTID_SIZE(&stream)) {
    case 0:
    case 1:
    case 2:
    case 4:
        break;
    default:
        LOGE("Invalid context ID size %d\n", CONTEXTID_SIZE(&stream));
        return EXIT_FAILURE;
        break;
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
