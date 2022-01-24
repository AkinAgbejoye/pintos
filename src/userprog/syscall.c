#include "userprog/syscall.h""
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "threads/init.h"
#include "lib/user/syscall.h"
static void syscall_handler (struct intr_frame *);
static  void readusermem(void* dest_addr, void* uaddr, size_t size);
static int user_mem_read_byte(const uint8_t* uaddr);
static struct file* findfilebyfd(int fd);
void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct fd_elem{

int fd;
struct file *file;
struct list_elem elem;
struct list_elem thread_elem;
};
static struct fd_elem* FindElemByFd(int fd);
static struct list file_list;
static struct lock *file_lock;



static void syscall_handler (struct intr_frame *f UNUSED)
{
  int syscall_num =  *((int*)f->esp);
  switch(syscall_num){
  case SYS_HALT:
	  halt();
	  break;
 case  SYS_EXIT:
	  {
	  int status;
	  readusermem(&status, f->esp+4, sizeof(status));
	  exit(status);
	  break;
	  }
 case SYS_FILESIZE:
	  {
	  int fd;
	  readusermem(&fd, f->esp + 4, sizeof(fd));
	 f->eax  =   filesize(fd);
	  break;
         }
 case SYS_CREATE:
	  {
	  const char* file;
	  unsigned initial_size;
	  readusermem(&file,f->esp +4, sizeof(file));
	  readusermem(&initial_size, f->esp + 8, sizeof(initial_size));
	  f->eax = create(file, initial_size);
	  break;
	  }
 case SYS_EXEC:
	  {
	  char *cmdline;
	  readusermem(&cmdline, f->esp+ 4, sizeof(cmdline));
	  f->eax = exec(cmdline);
	  break;
	  }
case SYS_SEEK:
	  {
	  unsigned position;
	  int fd;
	  readusermem(&fd, f->esp + 4, sizeof(fd));
	  seek(fd,position);
	  break;
	  }
default:
	  printf("WARNING: Invalid Syscall(%d)\n",syscall_num);
          thread_exit();
		  
  }


}


void halt(void){
/*
 *calls the powere shutdown function declared in threads/init.h
 */
shutdown_power_off();

}

void  exit(int status){
/*
 *get the current running thread
 */
struct thread *t;
t =  thread_current();
/*
 *intialize the status of the currentthread
 */
t->status = status;
/*
 *exit the thread
 */
thread_exit();

}

/*
 *run the excutable which name is given in the command and return the process id
 */
pid_t exec(const char *file){
pid_t  result;
if(!file )
  return -1;
  lock_acquire(&file_lock);  //file system in use
  result = process_execute(file);
  lock_release(&file_lock);

  return result;

}
static struct fd_elem*  findFdElemByFd(int fd){
struct fd_elem *result;
struct list_elem *l;
for(l = list_begin(&file_list); l != list_end(&file_list); l =list_next(l))
{
result = list_entry(l,struct fd_elem, elem);
if(result->fd == fd)
	return result;
}
return NULL;
}


/*
 *find the file descriptor from the memory
 */
static struct file* findfilebyfd(int fd){
struct fd_elem *result;
 result = findFdElemByFd(fd);
if(!result)
return NULL;
return result->file;
}

/*
 *this return the position of the next byte to be read from a file represented nby fd
 */
unsigned tell(int fd){

struct file *f;
f = findfilebyfd(fd);
if(!f)
 return -1;
return file_tell(f);
}

bool create(const char *file, unsigned initial_size)
{
if(!file)
   thread_exit();
return filesys_create(file,initial_size);

}	

int filesize(int fd)
{
struct file *f;
f = findfilebyfd(fd);
if(!f)
  return -1;
return file_length(f);
}


/*
 *change the next byte to be read oe written in open file to a position
 */
void seek(int fd, unsigned position)
{
struct file *f;
f = findfilebyfd(fd);
if(!f)
 thread_exit();
file_seek(f,position);

}

static int user_mem_read_byte(const uint8_t* uaddr){

int result; 
asm("movl $1f, %0; movzbl %1, %0;  1:": "=&a" (result) : "m" (*uaddr));
return result;
}

/*
 *As part of the systemcall, the kernel access memory through pointers provided by user program
 *The function has a destination address to save the result of memory read
 *starting memory location toread from
 * and the numbe rof nytes to be read
 * */
static void readusermem(void* dest_addr, void* uaddr, size_t size){

if(uaddr == NULL)
	thread_exit();
for(unsigned int i = 0; i < size; i++){

int byte_data = user_mem_read_byte(uaddr + i);
if(byte_data == -1) thread_exit;
*(uint8_t*) (dest_addr + i) = byte_data & 0xFF;
}

}
