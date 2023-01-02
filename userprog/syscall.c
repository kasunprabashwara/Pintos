#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame* f){
  switch(*(int*)f->esp){
    case SYS_HALT:{
      printf("halt");
      break;
    }
    case SYS_EXIT:{
      printf("exit");
      break;
    }
    case SYS_EXEC:{
      printf("exec");
      break;
    }
    case SYS_WAIT:{
      printf("wait");
      break;
    }
    case SYS_CREATE:{
      printf("create");
      break;
    }
    case SYS_REMOVE:{
      printf("remove");
      break;
    }
    case SYS_OPEN:{
      printf("open");
      break;
    }
    case SYS_FILESIZE:{
      printf("filesize");
      break;
    }
    case SYS_READ:{
      printf("read");
      break;
    }
    case SYS_WRITE:{
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);
      //run the syscall, a function of your own making
      //since this syscall returns a value, the return value should be stored in f->eax
      // f->eax = write(fd, buffer, size);
      printf("write");
      break;
    }
    case SYS_SEEK:{
      printf("seek");
      break;
    }
    case SYS_TELL:{
      printf("tell");
      break;
    }
    case SYS_CLOSE:{
      printf("close");
      break;
    }
  }
}
