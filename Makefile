CC=gcc

all: vuln

vuln: vuln.c
	$(CC) -o vuln -m32 -ggdb -Wno-deprecated-declarations -Wno-overflow -fno-stack-protector vuln.c -z execstack

clean:
	rm vuln