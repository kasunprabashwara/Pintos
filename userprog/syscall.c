#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "filesys/filesys.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
static void check_valid_ptr(void* ptr);
static void thread_force_exit(void);

struct lock syscall_lock;

void  
check_valid_ptr(void* ptr){
  if(ptr==NULL){
    thread_force_exit();
  }
  // check to if the pointer is in the user virtual address space
  if(!is_user_vaddr(ptr) || ptr<0x08048000){
    thread_force_exit();
  }
  // check to see if the pointer is mapped to a page
  if(pagedir_get_page(thread_current()->pagedir, ptr)==NULL){
    thread_force_exit();
  }
}
void
thread_force_exit(void){
  thread_current()->exit_status = -1;
  struct child* child=list_entry(&(thread_current()->child_elem), struct child, child_elem);
  child->exit_status = -1;
  thread_exit();
}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame* f){
  lock_init(&syscall_lock);

  switch(*(int*)f->esp){
    case SYS_HALT:{
      printf("halt");
      
      break;
    }
    case SYS_EXIT:{
      // free the thread's resources(iterate through the lists and free them)
      int status = (int)(*((int*)f->esp + 1));
      thread_current()->exit_status = status;
      struct child* child=list_entry(&(thread_current()->child_elem), struct child, child_elem);
      child->exit_status = status;
      list_remove(&thread_current()->child_elem);
      free(child);
      thread_exit();
      break;
    }
    case SYS_EXEC:{
      char* cmd_line = (char*)(*((int*)f->esp + 1));
      check_valid_ptr(cmd_line);
      tid_t tid = process_execute(cmd_line);
      sema_down(&thread_current()->sema); // wait for child to load
      if(thread_current()->child_load_success){
        f->eax = tid;
      }
      else{
        f->eax = -1;
      }
      break;
    }
    case SYS_WAIT:{
      tid_t tid = *((int*)f->esp + 1);
      f->eax = process_wait(tid);
      break;
    }
    case SYS_CREATE:{
      char* file = (char*)*((int*)f->esp + 1);
      check_valid_ptr(file);
      unsigned initial_size = *((unsigned*)f->esp + 2);
      f->eax = filesys_create (file, initial_size);
      break;

    }
    case SYS_REMOVE:{
      char* filepath = (char*)*((int*)f->esp + 1);
      check_valid_ptr(filepath);
      lock_acquire(&syscall_lock);
      f->eax = filesys_remove(filepath);
      lock_release(&syscall_lock);
      break;
    }
    case SYS_OPEN:{
      printf("open");
      char* file = *((int*)f->esp + 1);
      struct thread *temp_thread = thread_current ();
      struct fd_t *fd = malloc (sizeof (struct fd_t));
        if (filesys_open (file)) {
          fd->num = temp_thread->next_fd_num++;
          list_push_back (&temp_thread->fd_list, &fd->elem);
          f->eax = fd->num;
        }
        else {
          free (fd);
          f->eax = -1;
        }
      break;
    }

    case SYS_FILESIZE:{
      printf("filesize");
      int fd = *((int*)f->esp + 1);
      struct thread *current_thread = thread_current ();
      struct list_elem *e;
      for (e = list_begin (&current_thread->fd_list); e != list_end (&current_thread->fd_list); e = list_next (e)) {
        struct fd_t *fd = list_entry (e, struct fd_t, elem);
        if (fd->num == fd){
          if (!fd->is_dir)
            f->eax = file_length ((struct file *) fd->ptr);
          else
            f->eax = -1;
        }
      }
      f->eax -1;
      break;
    }

    case SYS_READ:{
      printf("read");
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);

      if (fd == 0){
        unsigned i;
        while ( i < size) {
          *((uint8_t *) buffer++) = input_getc ();
          i++;
        }
        return size;
      }
      else {
        struct thread *current_thread = thread_current ();
        struct list_elem *e;
        for (e = list_begin (&current_thread->fd_list); e != list_end (&current_thread->fd_list); e = list_next (e)) {
          struct fd_t *fdir = list_entry (e, struct fd_t, elem);
          if (fdir->num == fd){
            if (!fdir->is_dir)
              f->eax = file_read ((struct file *) fdir->ptr, buffer, size);
            else
              f->eax = -1;
          }
        }             

      }
      
      break;
    }
    
    case SYS_WRITE:{
      int fd = *((int*)f->esp + 1);
      void* buffer = (void*)(*((int*)f->esp + 2));
      unsigned size = *((unsigned*)f->esp + 3);
      //check to see if the buffer is valid
      check_valid_ptr(buffer);
      //run the syscall, a function of your own making
      //since this syscall returns a value, the return value should be stored in f->eax
      // f->eax = write(fd, buffer, size);
      if(fd==1){
        putbuf(buffer, size);
        f->eax=size;
        break;
      }
      else {
        struct thread *cur = thread_current ();
        struct list_elem *e;
        for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = list_next (e))
          {
            struct fd_t *fdir = list_entry (e, struct fd_t, elem);
            if (fdir->num == fd)
              {
                if (!fdir->is_dir)
                  return file_write ((struct file *) fdir->ptr, buffer, size);
                else
                  return -1;
        }
      return -1;
    }

      }
        
      
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
