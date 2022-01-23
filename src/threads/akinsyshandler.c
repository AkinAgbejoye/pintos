int syscall_number = *((int*)f->esp);
  switch (syscall_number) {
  case SYSCALL_HALT:
    syscall_halt(f);
    break;
  case SYSCALL_EXIT:
    syscall_exit(f);
    break;
  case SYSCALL_EXEC:
    syscall_exec(f);
    break;
  case SYSCALL_WAIT:
    syscall_wait(f);
    break;
  case SYSCALL_CREATE:
    syscall_create(f);
	  break;
  case SYSCALL_REMOVE:
	  syscall_remove(f);
	  break;
  case SYSCALL_WRITE:
    syscall_write(f);
    break;
  case SYSCALL_OPEN:
    syscall_open(f);
	  break;
  case SYSCALL_READ:
    syscall_read(f);
    break;
  case SYSCALL_FILESIZE:
	  syscall_filesize(f);
	  break;
  case SYSCALL_TELL:
    syscall_tell(f);
    break;
  case SYSCALL_SEEK:
	  syscall_seek(f);
	  break;
  case SYSCALL_CLOSE:
    syscall_close(f);
    break;
  default:
    printf ("WARNING: Invalid Syscall (%d)\n", syscall_number);
    thread_exit ();
  }
