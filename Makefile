CFLAGS := -g3 -O2 -Wall
LDFLAGS :=
SRCS := etmv4.c ptm.c ptm2human.c stream.c etb_format.c tracer-ptm.c
OBJS := $(SRCS:.c=.o)

CC ?= gcc
LD ?= ld

all: ptm2human

ptm2human: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c log.h pktproto.h stream.h tracer.h
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) ptm2human

.PHONY: clean all
