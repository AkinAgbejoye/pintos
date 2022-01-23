#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
struct fd_elem
  {
    int fd;
    struct file *file;
    struct list_elem elem;
    struct list_elem thread_elem;
  };
  static void readusermem(void* dest_addr, void* uaddr, size_t size);
sta 

static void syscall_handler (struct intr_frame *f UNUSED)
{
  int syscall_number = *((int*)f->esp);

  switch (syscall_number) {
  case SYSCALL_HALT:
        halt();
    break;
  case SYSCALL_EXIT:
        // get status from stack
        int status;
        readusermem(&status, f->esp + 4, sizeof (status));
        exit(status);
    break;
  case SYSCALL_FILESIZE:
	  readusermem(&fd, f->esp + 4, sizeof (fd));
       // syscall, return int
       f->eax = filesize(fd);
	  break;
  case SYSCALL_TELL:
	  int fd;
       readusermem(&fd, f->esp + 4, sizeof (fd));
        f->eax = tell(fd);
	  break;
  case SYSCALL_CREATE:
	  const char* file;
            unsigned int initial_size;
            readusermem(&file, f->esp + 4, sizeof (file));
            readusermem(&initial_size, f->esp + 8, sizeof (initial_size));
            f->eax = create(file, initial_size);  
  case SYSCALL_EXEC:
	   char *cmdline;
        readusermem(&cmdline, f->esp + 4, sizeof (cmdline));
        // syscall, return pid_t
         f->eax = exec(cmdline);	
  case SYSCALL_SEEK:
       unsigned position;
          int fd;
        readusermem(&fd, f->esp + 4, sizeof (fd));
         seek(fd,position);	  
 default:
    printf ("WARNING: Invalid Syscall (%d)\n", syscall_number);
    thread_exit ();
  }
  
}
void halt(void) {
  // terminate Pintos 
  shutdown_power_off();
}

int exit (int status)
{
  
  t->status = status;
  thread_exit ();
  return -1;
}


static struct file * find_file_by_fd (int fd)
{
  struct fd_elem *ret;
  
  ret = find_fd_elem_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

static struct fd_elem * find_fd_elem_by_fd (int fd)
{
  struct fd_elem *ret;
  struct list_elem *l;
  
  for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
    {
      ret = list_entry (l, struct fd_elem, elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}

static unsigned int tell (int fd)
{
  struct file *f;
  
  f = findfilebyfd (fd);
  if (!f)
    return -1;
  return file_tell (f);
}

pid_t exec (const char *cmdline)
{
  int result;
  
  if (!cmdline || !is_user_vaddr (cmdline)) /* bad ptr */
    return -1;
  lock_acquire (&file_lock);
  result = process_execute (cmd);
  lock_release (&file_lock);
  return result;
}
static int create (const char *file, unsigned initial_size)
{
  if (!file)
    return sys_exit (-1);
  return filesys_create (file, initial_size);
}

static int filesize (int fd)
{
  struct file *f;
  
  f = findfilebyfd (fd);
  if (!f)
    return -1;
  return file_length (f);
}

static int seek (int fd, unsigned pos)
{
  struct file *f;
  
  f = findfilebyfd (fd);
  if (!f)
    return -1;
  file_seek (f, pos);
  return 0; /* Not used */
}

static void readusermem(void* dest_addr, void* uaddr, size_t size) {
    // uaddr must be below PHYS_BASE and must not be NULL pointer
    if (uaddr == NULL || !is_user_vaddr(uaddr)) invalid_user_access();
    // read
    for (unsigned int i = 0; i < size; i++) {
        // read a byte from memory
        int byte_data = user_mem_read_byte(uaddr + i);
        // if byte_data = -1, the last memory read was a segment fault
        if (byte_data == -1) invalid_user_access();
        // save this byte of data to destination address
        *(uint8_t*) (dest_addr + i) = byte_data & 0xFF;
    }
}

static int user_mem_read_byte(const uint8_t* uaddr) {
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
                : "=&a" (result) : "m" (*uaddr));
    return result;
c
}
