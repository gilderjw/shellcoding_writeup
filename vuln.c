#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getinput()
{
  char buffer[64];
  printf("%p\n", buffer);

  printf("> "); 
  fflush(stdout);

  gets(buffer); // overflow happens here

  printf("\ngot input: %s\n", buffer);
}

int main(int argc, char **argv)
{
  getinput();
}