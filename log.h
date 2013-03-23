#ifndef _OUTPUT_H
#define _OUTPUT_H

#define LOGV(f, args...) fprintf(stdout, f, ## args)
#define LOGD(f, args...) fprintf(stderr, f, ## args)
#define LOGE(f, args...) fprintf(stderr, "ptm2human error: " f, ## args)

#endif
