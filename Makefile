CFLAGS=-Wall -Werror
LDFLAGS=-lgnutls

PROGS=sign verify

default: sign verify

sign: sign.o common.o
	gcc -o sign sign.o common.o $(LDFLAGS) $(CFLAGS)

verify: verify.o common.o
	gcc -o verify verify.o common.o $(LDFLAGS) $(CFLAGS)

%.o: %.c
	gcc -c $< $(CFLAGS)

clean:
	-rm -f *.o sign verify
