#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char* getinput()
{
  char buffer[64];
  printf("%p\n", buffer);

  printf("> "); 
  fflush(stdout);

  gets(buffer); // overflow happens here


  printf("got input: %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getinput();
}