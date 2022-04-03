default: remote

clean:
	rm -f trigger

remote: clean
	clang -Wall -o trigger \
		tcp.c \
		remote.c


