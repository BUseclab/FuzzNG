EXTRA_CFLAGS=-std=c99 -Werror -O3
LDFLAGS=-lpthread 
OBJ = main.o kcov.o virt2phys.o driver.o bloat.o user_access.o conveyor.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(EXTRA_CFLAGS)

fuzz: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS)

clean:
	rm -f *.o fuzz

ctags:
	ctags -R .
