#include <syscall.h>

int main (int, char *[]);
void _start (int argc, char *argv[]);

// Test Comment

void
_start (int argc, char *argv[]) 
{
  exit (main (argc, argv));
}
