#ifndef _OUTPUT_H
#define _OUTPUT_H

#define OUTPUT(f, args...) fprintf(stdout, f, ## args)

#endif
