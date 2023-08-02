CC=arm-linux-gnueabi-gcc
CFLAGS=-static

all: x r t

x: x.c
	$(CC) $(CFLAGS) -o x x.c

r: r.c
	$(CC) $(CFLAGS) -o r r.c

t: r.c
	$(CC) $(CFLAGS) -o t t.c

clean:
	rm -f x r t
