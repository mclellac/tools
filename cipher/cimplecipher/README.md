# Cimple Cipher a  Detection and Encryption Tool

## Overview
This program is a simple  tool for encrypting, decrypting, detecting, and brute-forcing ciphers commonly used in text-based cryptography.

## Features
- **Encryption and Decryption:** Supports Caesar, ROT13, Atbash, and Vigenère ciphers.
- **Cipher Detection:** Attempts to identify the cipher used on a given text by applying multiple ciphers.
- **Brute Force:** Attempts to brute force the key for the Vigenère cipher.
- **Dynamic Configuration:** Allows users to specify options such as cipher type, keys, and brute force parameters.

## Usage
### Command-Line Arguments
Run the program with the following options:

```bash
./cimplecipher [options] <file>
```

### Options
| Option             | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `-e <cipher>`      | Encrypt the file with the specified cipher (caesar, rot13, atbash, vigenere). |
| `-d <cipher>`      | Decrypt the file with the specified cipher.                                |
| `-k <key>`         | Key for Vigenère cipher (required for Vigenère encryption/decryption).       |
| `-t`               | Try to detect the cipher used in the file.                                 |
| `-b [max_length]`  | Brute force the Vigenère cipher key (optional max_length).                   |
| `-h`               | Display this help message.                                                 |

### Examples

#### Encrypt a File Using Caesar Cipher
```bash
./cimplecipher -e caesar input.txt
```

#### Decrypt a File Using Vigenère Cipher
```bash
./cimplecipher -d vigenere -k KEY input.txt
```

#### Detect Cipher Used on a File
```bash
./cimplecipher -t input.txt
```

#### Brute Force Vigenère Cipher Key
```bash
./cimplecipher -b 5 input.txt
```

## Building the Program

### Using Makefile
    Ensure you have make and a C compiler (e.g., GCC) installed.
    Build the program with:
```bash
make
```
Install the program to your `$HOME/bin` directory:
```bash
make install
```
Clean up build files:
```bash
make clean
```

### Without Makefile
If you prefer to compile manually:

    Compile the program:
```bash 
gcc -o cimplecipher main.c ciphers.c utils.c -Wall -Wextra -O2
```
Run the executable:
```bash
./cimplecipher
```

## Supported Ciphers

### Caesar Cipher
Shifts each letter in the text by a fixed number of positions in the alphabet. The shift amount can be customized.

### ROT13 Cipher
A special case of the Caesar cipher that shifts letters by 13 positions. Applying ROT13 twice restores the original text.

### Atbash Cipher
A substitution cipher that replaces each letter with its reverse counterpart in the alphabet (e.g., 'A' becomes 'Z').

### Vigenère Cipher
A polyalphabetic substitution cipher that uses a keyword to determine the shift for each letter.

## Limitations
- The brute force feature for the Vigenère cipher is limited to a maximum key length, which defaults to 10 but can be configured via the command-line option.
- Outputs of brute force and detection attempts are displayed without ranking their likelihood of correctness.

