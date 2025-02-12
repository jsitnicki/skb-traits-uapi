CC = clang -target bpf

%.bpf.o: %.bpf.c
	$(CC) -Wall -Wextra -ggdb -O2 -c -o $@ $<
