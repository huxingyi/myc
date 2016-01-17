TARGETS = libmyc libuvmyc example-client
CFLAGS= -g -I./include -I./examples/uvmyc/include
LDFLAGS= -g -luv -lm
AR=ar -rcs

all: $(TARGETS)

%.o: ./src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)
	
%.o: ./examples/uvmyc/src/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

libmyc: myc.o
	$(AR) ./lib/libmyc.a myc.o
	
libuvmyc: uvmyc.o myc.o
	$(AR) ./lib/libuvmyc.a uvmyc.o myc.o
	
example-client: example-client.o uvmyc.o myc.o
	$(CC) -o example-client example-client.o uvmyc.o myc.o $(LDFLAGS)
	
clean:
	rm -f $(TARGETS) *.o
