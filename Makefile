TARGETS = libmyc
CFLAGS= -g -I./include
LDFLAGS= -g
AR=ar -rcs

all: $(TARGETS)

%.o: ./src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

OBJS = 

libmyc: $(OBJS) myc.o
	$(AR) ./lib/libmyc.a myc.o
	
clean:
	rm -f $(TARGETS) *.o
