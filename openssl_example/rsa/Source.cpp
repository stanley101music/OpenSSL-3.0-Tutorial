#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#define RSA_KEY_SIZE 4096

size_t encrypt(unsigned char* in, size_t in_len, unsigned char*& out)
{
	FILE* fp = fopen("public.pem", "r");
	EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_encrypt_init(ctx);
	//EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	size_t out_len;
	EVP_PKEY_encrypt(ctx, NULL, &out_len, in, in_len);
	out = (unsigned char*)OPENSSL_zalloc(out_len);
	EVP_PKEY_encrypt(ctx, out, &out_len, in, in_len);
	return out_len;
}

size_t decrypt(unsigned char* in, size_t in_len, unsigned char*& out)
{
	FILE* fp = fopen("private.pem", "r");
	EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_decrypt_init(ctx);
	//EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	size_t out_len;
	EVP_PKEY_decrypt(ctx, NULL, &out_len, in, in_len);
	out = (unsigned char*)OPENSSL_zalloc(out_len);
	EVP_PKEY_decrypt(ctx, out, &out_len, in, in_len);
	return out_len;
}

int main()
{
	unsigned char* plaintext =
		(unsigned char*)"AES is based on a design principle known as a substitution¡Vpermutation network, and is efficient in both software and hardware. Unlike its predecessor DES, AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. By contrast, Rijndael per se is specified with block and key sizes that may be any multiple of 32 bits, with a minimum of 128 and a maximum of 256 bits.";
	size_t plaintext_len = strlen((char*)plaintext);
	unsigned char* ciphertext = NULL;
	size_t ciphertext_len = NULL;
	unsigned char* decryptedtext = NULL;
	size_t decryptedtext_len = NULL;

	// Generate key pairs
	// https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-RSA.html
	EVP_PKEY* pkey = EVP_RSA_gen(RSA_KEY_SIZE);

	// Save public key & private key
	FILE* fp = fopen("public.pem", "wt");
	PEM_write_PUBKEY(fp, pkey);
	fclose(fp);
	fp = fopen("private.pem", "wt");
	PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(fp);

	// Free
	EVP_PKEY_free(pkey);

	// Encryption
	ciphertext_len = encrypt(plaintext, plaintext_len, ciphertext);


	// Decryption
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, decryptedtext);

	printf("%s", decryptedtext);
	return 0;
}