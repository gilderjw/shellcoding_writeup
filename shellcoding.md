# Shellcode

## What is it?

Shellcode is a small piece of code written by an attacker of a software system. This code is run when a vulnerability a target application is exploited. For the purposes of this post, we will exploit this simple program:

<strong>vuln.c</strong>
```C
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char* getinput()
{
  char buffer[64];

  printf("> "); 
  fflush(stdout);

  gets(buffer); // overflow happens here

  printf("%p\n", buffer);

  printf("got input: %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getinput();
}
```

This simple program takes input from the user and prints it back. To get input from the user, the program uses the `gets()` function. This function is dangerous since it does not check for buffer overflow. For simplicity, we will compile this program for 32-bit linux, turn off [Address Space Layout Randomization (ASLR)](https://en.wikipedia.org/wiki/Address_space_layout_randomization), turn off [Stack Canaries](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries), and allow the stack to be executable. 

Turn off ASLR: 

`sudo sh -c "echo 0 >> /proc/sys/kernel/randomize_va_space"`

<strong>Makefile</strong>
```Make
CC=gcc

all: vuln

vuln: vuln.c
  $(CC) -o vuln -m32 -ggdb -Wno-deprecated-declarations -Wno-overflow -fno-stack-protector vuln.c -z execstack

clean:
  rm vuln
```

