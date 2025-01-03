#include "ciphers.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/*
 * Perform Caesar cipher encryption or decryption.
 * The Caesar cipher shifts each letter of the text by a fixed number of positions in the alphabet.
 *
 * @param text Input text to process.
 * @param shift Number of positions to shift the letters.
 * @param decrypt Flag to indicate decryption (1 for decryption, 0 for encryption).
 */
void caesar_cipher(const char *text, int shift, int decrypt) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = islower(text[i]) ? 'a' : 'A';
            printf("%c", (text[i] - base + (decrypt ? -shift : shift) + 26) % 26 + base);
        } else {
            printf("%c", text[i]);
        }
    }
    printf("\n");
}

/*
 * Perform ROT13 cipher encryption or decryption.
 * ROT13 is a special case of the Caesar cipher where letters are shifted by 13 positions.
 * Applying ROT13 twice restores the original text.
 *
 * @param text Input text to process.
 */
void rot13_cipher(const char *text) {
    caesar_cipher(text, 13, 0);
}

/*
 * Perform Atbash cipher encryption or decryption.
 * The Atbash cipher replaces each letter with its reverse counterpart in the alphabet.
 * For example, 'A' becomes 'Z', 'B' becomes 'Y', and so on.
 *
 * @param text Input text to process.
 */
void atbash_cipher(const char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = islower(text[i]) ? 'a' : 'A';
            printf("%c", base + ('Z' - text[i]) + ('a' - base));
        } else {
            printf("%c", text[i]);
        }
    }
    printf("\n");
}

/*
 * Perform Vigenère cipher encryption or decryption.
 * The Vigenère cipher uses a keyword to determine the shift for each letter.
 * Decryption reverses the shift using the same key.
 *
 * @param text Input text to process.
 * @param key Key to use for the cipher.
 * @param decrypt Flag to indicate decryption (1 for decryption, 0 for encryption).
 */
void vigenere_cipher(const char *text, const char *key, int decrypt) {
    int key_len = strlen(key);
    for (int i = 0, j = 0; text[i] != '\0'; i++) {
        if (isalpha(text[i])) {
            char base = islower(text[i]) ? 'a' : 'A';
            char k_base = islower(key[j % key_len]) ? 'a' : 'A';
            int shift = key[j % key_len] - k_base;
            if (decrypt) shift = -shift;
            printf("%c", (text[i] - base + shift + 26) % 26 + base);
            j++;
        } else {
            printf("%c", text[i]);
        }
    }
    printf("\n");
}

/*
 * Attempt to brute force the Vigenère cipher key and decrypt the text.
 * This function tries all possible keys up to a given length and applies decryption.
 *
 * @param text Input text to process.
 * @param max_length Maximum length of the key to try.
 */
void brute_force_vigenere(const char *text, int max_length) {
    char key[MAX_TEXT_LENGTH];
    for (int key_len = 1; key_len <= max_length; key_len++) {
        int max_combinations = 1;
        for (int i = 0; i < key_len; i++) {
            max_combinations *= 26;
        }
        for (int combination = 0; combination < max_combinations; combination++) {
            int temp = combination;
            for (int i = 0; i < key_len; i++) {
                key[i] = 'a' + (temp % 26);
                temp /= 26;
            }
            key[key_len] = '\0';
            printf("Key: %s\n", key);
            vigenere_cipher(text, key, 1);
        }
    }
}

/*
 * Attempt to detect the cipher used on the given text.
 * This function tries multiple ciphers (ROT13, Atbash, Caesar) and displays their outputs.
 *
 * @param text Input text to analyze.
 */
void detect_cipher(const char *text) {
    printf("ROT13 Output:\n");
    rot13_cipher(text);

    printf("Atbash Output:\n");
    atbash_cipher(text);

    printf("Caesar Cipher Outputs:\n");
    for (int shift = 1; shift <= 25; shift++) {
        printf("Shift %d: ", shift);
        caesar_cipher(text, shift, 1);
    }
}
