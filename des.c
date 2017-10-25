#include <openssl/des.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_BYTES 65536

#define ENC 0
#define DEC 1
#define ECB 2
#define CBC 3

int ACTION; // ENC or DEV
int MODE;   // ECB or CBC

int input_bytes; // number of bytes read from input file
int pad_bytes; // size of PKCS padding in bytes
int output_bytes; // number of bytes written to output file

// input and output buffers
char *input;
char *output;

// key and key schedule
DES_cblock key = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
DES_key_schedule keysched;

// ivec
DES_cblock ivec_init = { 0xE1, 0xE2, 0xE3, 0xD4, 0xD5, 0xC6, 0xC7, 0xA8 };
DES_cblock ivec;

// 8-byte buffers for encryption and decryption
DES_cblock* buf_in;
DES_cblock* buf_out;

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

void init_buffers() {
    buf_in = malloc(sizeof(DES_cblock) * 8);
    buf_out = malloc(sizeof(DES_cblock) * 8);
}

void free_buffers() {
    free(buf_in);
    free(buf_out);
}

void close_files() {
    fclose(input_file);
    fclose(output_file);
}

void ecb_encode() {
    input = malloc(sizeof(char) * (MAX_BYTES + 8));
    input_bytes = fread(input, sizeof(char), MAX_BYTES + 1, input_file);
    if (input_bytes > MAX_BYTES) {
        printf("Input file is too big, maximum is %d bytes.\n", MAX_BYTES);
        free(input);
        close_files();
        exit(1);
    }
    printf("Read %d bytes of input data...\n", input_bytes);

    pad_bytes = 8 - (input_bytes % 8);
    printf("Padding will be %d bytes long...\n", pad_bytes);
    for(int i = 0; i < pad_bytes; i++) input[input_bytes + pad_bytes - 1 - i] = pad_bytes;

    output = malloc(sizeof(char) * (input_bytes + pad_bytes));

    init_buffers();
    for (int i = 0; i < input_bytes + pad_bytes; i += 8) {
        memcpy(buf_in, input + i, 8);
        DES_ecb_encrypt(buf_in, buf_out, &keysched, DES_ENCRYPT);
        memcpy(output + i, buf_out, 8);
    }
    free_buffers();

    fwrite(output, sizeof(char), input_bytes + pad_bytes, output_file);

    free(input);
    free(output);
}

void ecb_decode() {
    input = malloc(sizeof(char) * (MAX_BYTES + 8 + 1));
    input_bytes = fread(input, sizeof(char), MAX_BYTES + 8 + 1, input_file);
    if (input_bytes > MAX_BYTES + 8) {
        printf("Input files is too big, maximum with padding is %d.\n", MAX_BYTES + 8);
        free(input);
        close_files();
        exit(1);
    }
    else if (input_bytes % 8 != 0) {
        printf("Input file content size is not a multiple of 8.\n");
        free(input);
        close_files();
        exit(1);
    }
    printf("Read %d bytes of input data...\n", input_bytes);

    output = malloc(sizeof(char) * input_bytes);

    init_buffers();
    for (int i = 0; i < input_bytes; i += 8) {
        memcpy(buf_in, input + i, 8);
        DES_ecb_encrypt(buf_in, buf_out, &keysched, DES_DECRYPT);
        memcpy(output + i, buf_out, 8);
    }
    free_buffers();

    pad_bytes = output[input_bytes - 1];
    printf("Padding is %d bytes...\n", pad_bytes);

    fwrite(output, sizeof(char), input_bytes - pad_bytes, output_file);

    free(input);
    free(output);
}

void cbc_encode() {
    input = malloc(sizeof(char) * (MAX_BYTES + 8));
    input_bytes = fread(input, sizeof(char), MAX_BYTES + 1, input_file);
    if (input_bytes > MAX_BYTES) {
        printf("Input file is too big, maximum is %d bytes.\n", MAX_BYTES);
        free(input);
        close_files();
        exit(1);
    }
    printf("Read %d bytes of input data...\n", input_bytes);

    pad_bytes = 8 - (input_bytes % 8);
    printf("Padding will be %d bytes long...\n", pad_bytes);
    for(int i = 0; i < pad_bytes; i++) input[input_bytes + pad_bytes - 1 - i] = pad_bytes;

    output = malloc(sizeof(char) * (input_bytes + pad_bytes));
    memcpy(ivec, ivec_init, sizeof(ivec_init));

    DES_ncbc_encrypt(input, output, input_bytes + pad_bytes, &keysched, &ivec, DES_ENCRYPT);

    fwrite(output, sizeof(char), input_bytes + pad_bytes, output_file);

    free(input);
    free(output);
}

void cbc_decode() {
    input = malloc(sizeof(char) * (MAX_BYTES + 8 + 1));
    input_bytes = fread(input, sizeof(char), MAX_BYTES + 8 + 1, input_file);
    if (input_bytes > MAX_BYTES + 8) {
        printf("Input files is too big, maximum with padding is %d.\n", MAX_BYTES + 8);
        free(input);
        close_files();
        exit(1);
    }
    else if (input_bytes % 8 != 0) {
        printf("Input file content size is not a multiple of 8.\n");
        free(input);
        close_files();
        exit(1);
    }
    printf("Read %d bytes of input data...\n", input_bytes);

    output = malloc(sizeof(char) * input_bytes);
    memcpy(ivec, ivec_init, sizeof(ivec_init));

    DES_ncbc_encrypt(input, output, input_bytes, &keysched, &ivec, DES_DECRYPT);

    pad_bytes = output[input_bytes - 1];
    printf("Padding is %d bytes...\n", pad_bytes);

    fwrite(output, sizeof(char), input_bytes - pad_bytes, output_file);

    free(input);
    free(output);
}

void main(int argc, char* argv[]) {
    if (argc < 5) print_usage_and_exit(argv[0]);
    parse_args(argv);
    DES_set_key(&key, &keysched);
    if (ACTION == ENC && MODE == ECB) ecb_encode();
    if (ACTION == DEC && MODE == ECB) ecb_decode();
    if (ACTION == ENC && MODE == CBC) cbc_encode();
    if (ACTION == DEC && MODE == CBC) cbc_decode();
    close_files();
}
