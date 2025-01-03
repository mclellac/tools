#include "utils.h"
#include "ciphers.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int encrypt = 0, decrypt = 0, detect = 0, brute_force = 0;
    int max_key_length = DEFAULT_KEY_LENGTH;
    char cipher[16] = "";
    char key[MAX_TEXT_LENGTH] = "";
    char *filename = NULL;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
            decrypt = 0;
            if (i + 1 < argc) {
                strncpy(cipher, argv[++i], 15);
            } else {
                fprintf(stderr, "%sError:%s Missing cipher name for -e\n", COLOR_RED, COLOR_RESET);
                return 1;
            }
        } else if (strcmp(argv[i], "-d") == 0) {
            decrypt = 1;
            encrypt = 0;
            if (i + 1 < argc) {
                strncpy(cipher, argv[++i], 15);
            } else {
                fprintf(stderr, "%sError:%s Missing cipher name for -d\n", COLOR_RED, COLOR_RESET);
                return 1;
            }
        } else if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) {
                strncpy(key, argv[++i], MAX_TEXT_LENGTH - 1);
            } else {
                fprintf(stderr, "%sError:%s Missing key for Vigenère cipher\n", COLOR_RED, COLOR_RESET);
                return 1;
            }
        } else if (strcmp(argv[i], "-t") == 0) {
            detect = 1;
        } else if (strcmp(argv[i], "-b") == 0) {
            brute_force = 1;
            if (i + 1 < argc && isdigit(argv[i + 1][0])) {
                max_key_length = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            filename = argv[i];
        }
    }

    if (!filename) {
        fprintf(stderr, "%sError:%s No input file specified\n", COLOR_RED, COLOR_RESET);
        return 1;
    }

    // Open and read the file
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    char text[MAX_TEXT_LENGTH] = {0};
    char line[MAX_TEXT_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        // Skip empty lines
        if (line[0] == '\n') {
            continue;
        }
        strncat(text, line, sizeof(text) - strlen(text) - 1);
    }
    fclose(file);

    if (strlen(text) == 0) {
        fprintf(stderr, "%sError:%s Input file is empty or contains only empty lines\n", COLOR_RED, COLOR_RESET);
        return 1;
    }

    // Process based on user input
    if (brute_force) {
        brute_force_vigenere(text, max_key_length);
    } else if (detect) {
        detect_cipher(text);
    } else if (encrypt || decrypt) {
        if (strcmp(cipher, "caesar") == 0) {
            caesar_cipher(text, DEFAULT_SHIFT, decrypt);
        } else if (strcmp(cipher, "rot13") == 0) {
            rot13_cipher(text);
        } else if (strcmp(cipher, "atbash") == 0) {
            atbash_cipher(text);
        } else if (strcmp(cipher, "vigenere") == 0) {
            if (strlen(key) == 0) {
                fprintf(stderr, "%sError:%s Vigenère cipher requires a key\n", COLOR_RED, COLOR_RESET);
                return 1;
            }
            vigenere_cipher(text, key, decrypt);
        } else {
            fprintf(stderr, "%sError:%s Unknown cipher '%s'\n", COLOR_RED, COLOR_RESET, cipher);
            return 1;
        }
    } else {
        print_usage(argv[0]);
    }

    return 0;
}
