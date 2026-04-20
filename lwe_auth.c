#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define LWE_N 128
#define LWE_M 256
#define ERROR_MAX 2
#define MAC_SIZE 32

typedef struct {
    uint16_t A[LWE_M * LWE_N];
    uint16_t b[LWE_M];
} PublicKey;

typedef struct {
    uint16_t s[LWE_N];
    uint8_t mac_key[MAC_SIZE];
} PrivateKey;

void secure_random_bytes(uint8_t *buf, size_t len) {
    if (RAND_bytes(buf, len) != 1) {
        perror("Falha no CSPRNG do OpenSSL");
        exit(EXIT_FAILURE);
    }
}

uint16_t sample_noise() {
    uint8_t rand_byte;
    secure_random_bytes(&rand_byte, 1);
    int val = (rand_byte % (ERROR_MAX * 2 + 1)) - ERROR_MAX;
    return (uint16_t)val; 
}

void generate_keys(PublicKey *pk, PrivateKey *sk) {
    secure_random_bytes((uint8_t*)sk->s, LWE_N * sizeof(uint16_t));
    secure_random_bytes(sk->mac_key, MAC_SIZE);

    for (int i = 0; i < LWE_M; i++) {
        uint16_t sum = 0;
        for (int j = 0; j < LWE_N; j++) {
            uint16_t a_val;
            secure_random_bytes((uint8_t*)&a_val, sizeof(uint16_t));
            pk->A[i * LWE_N + j] = a_val;
            sum += (uint16_t)( (uint32_t)a_val * (uint32_t)sk->s[j] ); 
        }
        pk->b[i] = sum + sample_noise();
    }
}

void encrypt_bit(uint8_t bit, const PublicKey *pk, uint16_t *u, uint16_t *v) {
    memset(u, 0, LWE_N * sizeof(uint16_t));
    uint16_t v_sum = 0;

    for (int i = 0; i < LWE_M; i++) {
        uint8_t r_byte;
        secure_random_bytes(&r_byte, 1);
        uint16_t mask = (r_byte & 1) ? 0xFFFF : 0x0000; 

        v_sum += (pk->b[i] & mask);
        for (int j = 0; j < LWE_N; j++) {
            u[j] += (pk->A[i * LWE_N + j] & mask);
        }
    }
    *v = v_sum + (bit ? 32768 : 0); 
}

uint8_t decrypt_bit(const uint16_t *u, uint16_t v, const PrivateKey *sk) {
    uint16_t sum = 0;
    for (int j = 0; j < LWE_N; j++) {
        sum += (uint16_t)( (uint32_t)u[j] * (uint32_t)sk->s[j] );
    }
    uint16_t extracted_noise = v - sum;
    
    /* A CORRECAO: Forçando a soma a se manter em 16-bits ANTES do shift */
    return (uint8_t)( ((uint16_t)(extracted_noise + 16384)) >> 15 );
}

int constant_time_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void encrypt_buffer(const uint8_t *data, size_t len, const PublicKey *pk, const PrivateKey *sk, uint16_t *out_u, uint16_t *out_v, uint8_t *out_mac) {
    size_t out_idx = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        for (int bit = 0; bit < 8; bit++) {
            uint8_t msg_bit = (byte >> bit) & 1;
            encrypt_bit(msg_bit, pk, &out_u[out_idx * LWE_N], &out_v[out_idx]);
            out_idx++;
        }
    }

    unsigned int mac_len;
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, sk->mac_key, MAC_SIZE, EVP_sha256(), NULL);
    HMAC_Update(ctx, (uint8_t*)out_u, len * 8 * LWE_N * sizeof(uint16_t));
    HMAC_Update(ctx, (uint8_t*)out_v, len * 8 * sizeof(uint16_t));
    HMAC_Final(ctx, out_mac, &mac_len);
    HMAC_CTX_free(ctx);
}

int decrypt_buffer(const uint16_t *in_u, const uint16_t *in_v, const uint8_t *in_mac, size_t len, const PrivateKey *sk, uint8_t *out_data) {
    uint8_t calculated_mac[MAC_SIZE];
    unsigned int mac_len;
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, sk->mac_key, MAC_SIZE, EVP_sha256(), NULL);
    HMAC_Update(ctx, (const uint8_t*)in_u, len * 8 * LWE_N * sizeof(uint16_t));
    HMAC_Update(ctx, (const uint8_t*)in_v, len * 8 * sizeof(uint16_t));
    HMAC_Final(ctx, calculated_mac, &mac_len);
    HMAC_CTX_free(ctx);

    if (!constant_time_memcmp(in_mac, calculated_mac, MAC_SIZE)) {
        return 0;
    }

    size_t in_idx = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            uint8_t msg_bit = decrypt_bit(&in_u[in_idx * LWE_N], in_v[in_idx], sk);
            byte |= (msg_bit << bit);
            in_idx++;
        }
        out_data[i] = byte;
    }
    return 1;
}

int main() {
    PublicKey pk;
    PrivateKey sk;

    printf("[*] Iniciando gerador de entropia do OpenSSL...\n");
    printf("[*] Gerando chaves LWE (Dimensao %d, Espaco 16-bits)...\n", LWE_N);
    generate_keys(&pk, &sk);

    const char *mensagem = "Defesa profunda com Kernel Entropy e HMAC-SHA256.";
    size_t msg_len = strlen(mensagem);
    size_t bits_len = msg_len * 8;

    uint16_t *cifrado_u = malloc(bits_len * LWE_N * sizeof(uint16_t));
    uint16_t *cifrado_v = malloc(bits_len * sizeof(uint16_t));
    uint8_t *mac_assinatura = malloc(MAC_SIZE);
    uint8_t *decifrado = malloc(msg_len + 1);

    printf("[*] Criptografando e assinando %zu bytes...\n", msg_len);
    encrypt_buffer((const uint8_t*)mensagem, msg_len, &pk, &sk, cifrado_u, cifrado_v, mac_assinatura);

    printf("[*] Checando integridade CCA2 e Descriptografando...\n");
    
    if (decrypt_buffer(cifrado_u, cifrado_v, mac_assinatura, msg_len, &sk, decifrado)) {
        decifrado[msg_len] = '\0';
        printf("\n[+] Integridade Validada!\n");
        printf("[+] Mensagem Restaurada: %s\n", decifrado);
    } else {
        printf("\n[!] ALERTA CRITICO: Ciphertext modificado. Descriptografia abortada.\n");
    }

    free(cifrado_u); free(cifrado_v); free(mac_assinatura); free(decifrado);
    return 0;
}
