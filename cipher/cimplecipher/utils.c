#include "utils.h"
#include <stdio.h>

#define COLOR_RESET "\033[0m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_RED "\033[1;31m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"

void print_usage(const char *prog_name) {
    printf("%sUsage:%s %s [options] <file>\n", COLOR_YELLOW, COLOR_RESET, prog_name);
    printf("%sOptions:%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  %s-e <cipher>%s    Encrypt the file with the specified cipher (caesar, rot13, atbash, vigenere)\n", COLOR_GREEN, COLOR_RESET);
    printf("  %s-d <cipher>%s    Decrypt the file with the specified cipher\n", COLOR_GREEN, COLOR_RESET);
    printf("  %s-k <key>%s       Key for Vigenère cipher (required for Vigenère encryption/decryption)\n", COLOR_GREEN, COLOR_RESET);
    printf("  %s-t%s             Try to detect the cipher used in the file\n", COLOR_GREEN, COLOR_RESET);
    printf("  %s-b [max_length]%s Brute force the Vigenère cipher key (optional max_length)\n", COLOR_GREEN, COLOR_RESET);
    printf("  %s-h%s             Show this help message\n", COLOR_GREEN, COLOR_RESET);
}
