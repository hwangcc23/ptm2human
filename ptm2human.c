#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "log.h"
#include "stream.h"

static const struct option options[] = {
    { "input", 1, 0, 'i' },
    { "context", 1, 0, 'c' },
    { "cycle-accurate", 0, 0, 'C' },
    { "help", 0, 0, 'h' },
    { NULL, 0, 0, 0   },
};

static const char *optstring = "i:c:Ch";

void usage(void)
{
}

int file2buff(const char *input_file, const char *buff, unsigned int buff_len)
{
	int fd;

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
    int longindex, c, ret;
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
            stream.contextid_size = atoi(optarg);
            break;

        case 'C':
            stream.cycle_accurate = 1;
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

    /* validate context ID size */
    switch (stream.contextid_size) {
    case 0:
    case 1:
    case 2:
    case 4:
        break;
    default:
        LOGE("Invalid context ID size %d\n", stream.contextid_size);
        return EXIT_FAILURE;
        break;
    }

    ret = stat(input_file, &sb);
    if (ret == -1) {
        LOGE("Cannot stat %s (%s)\n", input_file, strerror(errno));
        return EXIT_FAILURE;
    }

    stream.buff_len = sb.st_size / 2 + 1;
    stream.buff = malloc(stream.buff_len);
    if (!(stream.buff)) {
        LOGE("Fail to allocate memory (%s)\n", strerror(errno));
        return EXIT_FAILURE;
    }
    memset((void *)stream.buff, 0, stream.buff_len);

    file2buff(input_file, stream.buff, stream.buff_len);

    ret = decode_stream(&stream);

    free((void *)stream.buff);

    return EXIT_SUCCESS;
}
