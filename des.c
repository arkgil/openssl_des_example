#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_BYTES 1024

#define ENC 0
#define DEC 1
#define ECB 2
#define CBC 3

int ACTION;
int MODE;

// key and key schedule
DES_cblock key = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
DES_key_schedule keysched;

// 8-byte buffers for encryption and decryption
unsigned char buf_in[8];
unsigned char buf_out[8];

// input and output file handles
FILE* input_file;
FILE* output_file;

void print_usage_and_exit(char* progname) {
    printf("Usage: %s enc|dec ecb|cbc <input_file> <output_file>\n", progname);
    exit(1);
}

void parse_args(char* argv[]) {
    int failed = 0;

    char* action = argv[1];
    if (strcmp(action, "enc") == 0) ACTION = ENC;
    else if (strcmp(action, "dec") == 0) ACTION = DEC;
    else {
        printf("Expected `enc` or `dec` as a first argument, got \"%s\".\n", action);
        failed = 1;
    }

    char* mode = argv[2];
    if (strcmp(mode, "ecb") == 0) MODE = ECB;
    else if (strcmp(mode, "cbc") == 0) MODE = CBC;
    else {
        printf("Expected `ecb` or `cbc` as a second argument, got \"%s\".\n", mode);
        failed = 1;
    }

    char* input_filename = argv[3];
    input_file = fopen(input_filename, "r");
    if (input_file == NULL) {
        printf("Can't open input file `%s`.\n", input_filename);
        failed = 1;
    }

    char* output_filename = argv[4];
    output_file = fopen(output_filename, "w");

    if (failed == 1) print_usage_and_exit(argv[0]);
}

void close_files() {
    fclose(input_file);
    fclose(output_file);
}

void main(int argc, char* argv[]) {
    if (argc < 5) print_usage_and_exit(argv[0]);
    parse_args(argv);
    DES_set_key(&key, &keysched);
    close_files();
}
