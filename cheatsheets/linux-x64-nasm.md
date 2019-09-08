# x64 NASM cheat sheet

## Registers

|                         | 64 bit | 32 bit | 16 bit | 8 bit |
|-------------------------|--------|--------|--------|-------|
| A (accumulator)         | `RAX`  | `EAX`  | `AX`   | `AL`  |
| B (base, addressing)    | `RBX`  | `EBX`  | `BX`   | `BL`  |
| C (counter, iterations) | `RCX`  | `ECX`  | `CX`   | `CL`  |
| D (data)                | `RDX`  | `EDX`  | `DX`   | `DL`  |
|                         | `RDI`  | `EDI`  | `DI`   | `DIL` |
|                         | `RSI`  | `ESI`  | `SI`   | `SIL` |
| Numbered (n=8..15)      | `Rn`   | `RnD`  | `RnW`  | `RnB` |
| Stack pointer           | `RSP`  | `ESP`  | `SP`   | `SPL` |
| Frame pointer           | `RBP`  | `EBP`  | `BP`   | `BPL` |

As well as XMM0 .. XMM15 for 128 bit floating point numbers.


## Calling C

Put function arguments (first to last) in the following registers (64 bit
representations): RDI, RSI, RDX, RCX, R8, R9, then push to stack (in reverse,
has to be cleaned up by the caller!) XMM0 - XMM7 for floats

Return values are stored in RAX (`int`) or XMM0 (`float`)

RBP, RBX, R12, R13, R14, R15 will not be changed by the called function, all
others may be

Align stack pointer (RSP) to 16 byte, calling pushes 8 bytes!

Keep in mind that strings (in C) are 0-terminated

Like in a normal C program, the label that is (de facto) called first is
`main`, with the args `argc` (argcount) in RDI, and the `char** argv` in RSI
(the commandline arguments as in C's main function).


## Data

| Definition size    | Definition instruction |
|--------------------|------------------------|
| 8 bit              | `db`                   |
| 16 bit             | `dw`                   |
| 32 bit             | `dd`                   |
| 64 bit             | `ddq`/`do`             |
| float              | `dd`                   |
| double             | `dq`                   |
| extended precision | `dt`                   |


## Conditionals

`cmp op1, op2` -> mimics `sub op1, op2` but only changes the zero and carry flag
for comparing.

Prefixes:

- `j~ x`       -> jump to x if ~
- `cmov~ x, y` -> conditional mov x, y if ~
- `setc~ x`    -> set x to 1 if ~, x is 8 bit reg

Many suffixes, including:

- `a` (above, >)
- `ae` (above or equal, >=)
- `b` (below, <)
- `be` (below or equal, <=)
- `e` (equal, =)
- `ne` (not equal, !=)


## Program structure

- `global <entry>` -> exposes entry point
- `extern <function>` -> declares a function in another linked .o file (e.g. C
  function, other asm file)
- `section <sectiontype>` -> sets section, usually:
  - `.text` -> program code
  - `.data` -> data

The program entry point of a standalone program is the label `_start`.  When
compiled with gcc, C provides `_start`, which inits and then jumps to `main`,
which should then be implemented by the program.


## Syscalls

- put syscall number in EAX (e.g. on Linux: 60 for exit, 1 for write to stdout)
- put arguments in the registers (see above) like when calling a C function
- execute the `syscall` instruction


## Assemble

- Assemble: `nasm -felf64 -o <object> <filename>`
- Link with ld: `ld -o <output> <object>`
- Link with gcc: `gcc -o <output> <object>`


## Sources

- Forked from: [mpdrescher](https://github.com/mpdrescher/linux-x64-nasm-cheatsheet)
- Main: [NASM Tutorial](http://cs.lmu.edu/~ray/notes/nasmtutorial)
- Registers: [Assembly registers](https://tutorialspoint.com/assembly_programming/assembly_registers.htm)
- Conditionals: [Jumps and loops (de)](https://de.wikibooks.org/wiki/Assembler-Programmierung_für_x86-Prozessoren/_Sprünge_und_Schleifen)