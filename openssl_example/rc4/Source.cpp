#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <string.h>
#include <cassert>
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#define RC4_KEY_SIZE 16
#define RC4_BLOCK_SIZE 8

int RC4(unsigned char* in, int in_len, unsigned char* key, unsigned char* iv, const EVP_CIPHER* cipher_type, unsigned int crypt_mode, unsigned char*& out)
{
    int out_len1, out_len2;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (crypt_mode == 1)
        out = (unsigned char*)OPENSSL_zalloc(in_len + RC4_BLOCK_SIZE);
    else
        out = (unsigned char*)OPENSSL_zalloc(in_len);
    EVP_CipherInit_ex(ctx, cipher_type, NULL, key, iv, crypt_mode);
    EVP_CipherUpdate(ctx, out, &out_len1, in, in_len);
    EVP_CipherFinal_ex(ctx, out + out_len1, &out_len2);
    EVP_CIPHER_CTX_cleanup(ctx);
    return out_len1 + out_len2;
}

// For simplicity, I've removed all the error handling functions
int main()
{
    OSSL_PROVIDER* legacy;
    OSSL_PROVIDER* deflt;
    legacy = OSSL_PROVIDER_load(NULL, "legacy");
    deflt = OSSL_PROVIDER_load(NULL, "default");

    unsigned char key[RC4_KEY_SIZE];
    unsigned char iv[RC4_BLOCK_SIZE];
    // All kinds of cryptography algorithm can be found in https://github.com/openssl/openssl/blob/master/include/openssl/evp.h
    const EVP_CIPHER* cipher_type = EVP_rc4();

    // plaintext is taken from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_ciphers
    unsigned char* plaintext =
        (unsigned char*)"AES is based on a design principle known as a substitutioníVpermutation network, and is efficient in both software and hardware. Unlike its predecessor DES, AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. By contrast, Rijndael per se is specified with block and key sizes that may be any multiple of 32 bits, with a minimum of 128 and a maximum of 256 bits.";
    int plaintext_len = strlen((char*)plaintext);
    unsigned char* ciphertext = NULL;
    int ciphertext_len;
    unsigned char* decryptedtext = NULL;
    int decryptedtext_len;

    // Generate cryptographically strong pseudo-random bytes for key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // crypt_mode = 1 -> encrypt
    // crypt_mode = 0 -> decrypt
    unsigned int crypt_mode = 1;
    // Encryption
    ciphertext_len = RC4(plaintext, plaintext_len, key, iv, cipher_type, crypt_mode, ciphertext);

    // Decryption
    crypt_mode = 0;
    decryptedtext_len = RC4(ciphertext, ciphertext_len, key, iv, cipher_type, crypt_mode, decryptedtext);

    printf("%s", decryptedtext);
    return 0;
}