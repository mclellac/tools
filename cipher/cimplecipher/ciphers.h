
#ifndef CIPHERS_H
#define CIPHERS_H

void caesar_cipher(const char *text, int shift, int decrypt);
void rot13_cipher(const char *text);
void atbash_cipher(const char *text);
void vigenere_cipher(const char *text, const char *key, int decrypt);
void brute_force_vigenere(const char *text, int max_length);
void detect_cipher(const char *text);

#endif
