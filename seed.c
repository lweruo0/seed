#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define WORD_COUNT 2048
#define WORD_SIZE 32
#define INPUT_SIZE 7

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char buffer[64];
    size_t buffer_size;
} Sha256;

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32 - bits));
}

static void sha256_transform(Sha256 *ctx, const unsigned char block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256 *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bit_count = 0;
    ctx->buffer_size = 0;
}

static void sha256_update(Sha256 *ctx, const unsigned char *data, size_t length) {
    while (length > 0) {
        size_t available = 64 - ctx->buffer_size;
        size_t amount = length < available ? length : available;
        memcpy(ctx->buffer + ctx->buffer_size, data, amount);
        ctx->buffer_size += amount;
        ctx->bit_count += (uint64_t)amount * 8;
        data += amount;
        length -= amount;
        if (ctx->buffer_size == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_size = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, unsigned char digest[32]) {
    size_t i;
    unsigned char length_bytes[8];
    uint64_t bit_count = ctx->bit_count;

    ctx->buffer[ctx->buffer_size++] = 0x80;
    while (ctx->buffer_size != 56) {
        if (ctx->buffer_size == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_size = 0;
        }
        ctx->buffer[ctx->buffer_size++] = 0;
    }
    for (i = 0; i < 8; ++i) {
        length_bytes[7 - i] = (unsigned char)(bit_count >> (i * 8));
    }
    memcpy(ctx->buffer + 56, length_bytes, 8);
    sha256_transform(ctx, ctx->buffer);
    for (i = 0; i < 8; ++i) {
        digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)ctx->state[i];
    }
}

static int dice_index(const char *dice, int *index) {
    int value = 0;
    size_t i;
    if (strlen(dice) != 6) return 0;
    for (i = 0; i < 6; ++i) {
        if (dice[i] < '1' || dice[i] > '4') return 0;
        value = value * 4 + (dice[i] - '1');
    }
    *index = value;
    return value < WORD_COUNT;
}

static int load_words(const char *path, char words[WORD_COUNT][WORD_SIZE]) {
    FILE *file = fopen(path, "r");
    int count = 0;
    if (!file) return 0;
    while (count < WORD_COUNT && fscanf(file, "%31s", words[count]) == 1) ++count;
    fclose(file);
    return count == WORD_COUNT;
}

static int find_word(char words[WORD_COUNT][WORD_SIZE], const char *word) {
    int i;
    for (i = 0; i < WORD_COUNT; ++i) {
        if (strcmp(words[i], word) == 0) return i;
    }
    return -1;
}

static int checksum_word(char words[WORD_COUNT][WORD_SIZE], const char *dice,
                         char first_23[23][WORD_SIZE], char result[WORD_SIZE]) {
    unsigned char entropy[32] = {0};
    unsigned char digest[32];
    Sha256 sha;
    int dice_value;
    int suffix;
    int final_index;
    int bit_position = 0;
    int i;

    if (strlen(dice) != 6) return 0;
    dice_value = 0;
    for (i = 0; i < 6; ++i) {
        if (dice[i] < '1' || dice[i] > '4') return 0;
        dice_value = dice_value * 4 + (dice[i] - '1');
    }
    suffix = dice_value >> 9;

    for (i = 0; i < 23; ++i) {
        int index = find_word(words, first_23[i]);
        int bit;
        if (index < 0) return 0;
        for (bit = 10; bit >= 0; --bit, ++bit_position) {
            if (index & (1 << bit)) entropy[bit_position / 8] |=
                (unsigned char)(1 << (7 - (bit_position % 8)));
        }
    }
    for (i = 2; i >= 0; --i, ++bit_position) {
        if (suffix & (1 << i)) entropy[bit_position / 8] |=
            (unsigned char)(1 << (7 - (bit_position % 8)));
    }

    sha256_init(&sha);
    sha256_update(&sha, entropy, sizeof(entropy));
    sha256_final(&sha, digest);
    final_index = (suffix << 8) | digest[0];
    strcpy(result, words[final_index]);
    return 1;
}

int main(int argc, char **argv) {
    char words[WORD_COUNT][WORD_SIZE];
    char dice[24][INPUT_SIZE];
    char first_23[23][WORD_SIZE];
    char result[WORD_SIZE];
    const char *wordlist_path = argc > 1 ? argv[1] : "wordlist.txt";
    int i;
    int index;

    if (!load_words(wordlist_path, words)) {
        fprintf(stderr, "Fehler: %s muss genau 2048 BIP39-Wörter enthalten.\n", wordlist_path);
        return 1;
    }

    printf("Gib 24 Dice-Strings mit je sechs Ziffern (1-4) ein.\n");
    for (i = 0; i < 24; ++i) {
        printf("%2d: ", i + 1);
        if (scanf("%6s", dice[i]) != 1) return 1;
        if (i < 23) {
            if (!dice_index(dice[i], &index)) {
                fprintf(stderr, "Ungültiges Ergebnis bei Wort %d; bitte neu würfeln.\n", i + 1);
                return 1;
            }
            strcpy(first_23[i], words[index]);
            printf("%s\n", first_23[i]);
        }
    }

    if (!checksum_word(words, dice[23], first_23, result)) {
        fprintf(stderr, "Ungültiger Dice-String für das 24. Wort.\n");
        return 1;
    }
    printf("24: %s\n", result);
    printf("\nMnemonic:\n");
    for (i = 0; i < 23; ++i) printf("%s ", first_23[i]);
    printf("%s\n", result);
    return 0;
}
