#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

int padding = RSA_NO_PADDING, mod_v = 0, mod_d = 0, mod_s = 0;

unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
								0x06, 0x09, 0x60, 0x86,
								0x48, 0x01, 0x65, 0x03,
								0x04, 0x02, 0x03, 0x05,
								0x00, 0x04, 0x40};

unsigned char EMSASHAID[] = {0x30, 0x21, 0x30, 0x09, 0x06,
							 0x05, 0x2b, 0x0E, 0x03, 0x02,
							 0x1A, 0x05, 0x00, 0x04, 0x14};

void printHex(char *name, unsigned char *hex, int length)
{
	int i;

	fprintf(stderr, "%s: ", name);

	for(i = 0; i < length; ++i)
		fprintf(stderr, "%02x", hex[i]);

	fprintf(stderr, "\n%s Length: %d\n\n", name, length);
}

char *getHex(unsigned char *hash)
{
	int i, length = SHA512_DIGEST_LENGTH;
	char *aux = malloc(length * 2);

	for(i = 0; i < length; ++i)
		sprintf(aux + (i * 2), "%02x", hash[i]);

	return aux;
}

unsigned char *doHash(char *name)
{
	SHA_CTX c;
	char buf[1024];
	unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
	int fd, bytes_leidos;

	if((fd = open(name, O_RDONLY)) < 0)
		errx(1, "Unable to open text file");

	if(SHA1_Init(&c) == 0)
		errx(1, "SHA1_Init failed");

	while((bytes_leidos = read(fd, buf, 1)) > 0)
		if(SHA1_Update(&c, buf, bytes_leidos) == 0)
			errx(1, "SHA1_Update failed");

	if(SHA1_Update(&c, name, strlen(name)) == 0)
			errx(1, "SHA1_Update failed");

	if(SHA1_Final(hash, &c) == 0)
		errx(1, "SHA1_Final failed");

	close(fd);

	return hash;
}

unsigned char *doHash512(char *name)
{
	SHA512_CTX c;
	char buf[1024];
	unsigned char *hash = malloc(SHA512_DIGEST_LENGTH);
	int fd, bytes_leidos, i;

	if((fd = open(name, O_RDONLY)) < 0)
		errx(1, "Unable to open text file");

	if(SHA512_Init(&c) == 0)
		errx(1, "SHA512_Init failed");

	while((bytes_leidos = read(fd, buf, 1)) > 0)
		if(SHA512_Update(&c, buf, bytes_leidos) == 0)
			errx(1, "SHA512_Update failed");

	if(SHA512_Update(&c, name, strlen(name)) == 0)
			errx(1, "SHA512_Update failed");

	if(SHA512_Final(hash, &c) == 0)
		errx(1, "SHA512_Final failed");

	close(fd);

	for(i = 0; i < 2; ++i){
		if(SHA512_Init(&c) == 0)
			errx(1, "SHA512_Init failed");

		if(SHA512_Update(&c, getHex(hash), SHA512_DIGEST_LENGTH * 2) == 0)
				errx(1, "SHA512_Update failed");

		if(SHA512_Final(hash, &c) == 0)
			errx(1, "SHA512_Final failed");
	}

	return hash;
}

int getTlength()
{
	if(mod_s)
		return sizeof(EMSASHAID) + SHA_DIGEST_LENGTH;
	else
		return sizeof(EMSASHA512ID) + SHA512_DIGEST_LENGTH;
}

unsigned char *doT(unsigned char *hash)
{
	unsigned char *T = malloc(getTlength());

	if(mod_s) {
		memcpy(T, EMSASHAID, sizeof(EMSASHAID));
		memcpy(T + sizeof(EMSASHAID), hash, SHA_DIGEST_LENGTH);
	} else {
		memcpy(T, EMSASHA512ID, sizeof(EMSASHA512ID));
		memcpy(T + sizeof(EMSASHA512ID), hash, SHA512_DIGEST_LENGTH);
	}

	return T;
}

int getPSlength()
{
	return (4096/8) - getTlength() - 3;
}

unsigned char *doPS()
{
	unsigned char *PS = malloc(getPSlength());

	memset(PS, 0xff, getPSlength());

	return PS;
}

unsigned char *doData(char *name)
{
	unsigned char *data = malloc(4096/8), *hash, *T, *PS;
	int lenPS = getPSlength();
	int lenT = getTlength();

	if(mod_s)
		hash = doHash(name);
	else
		hash = doHash512(name);
	T = doT(hash);
	PS = doPS();
	memset(data, 0x00, 1);
	memset(data + 1, 0x01, 1);
	memcpy(data + 2, PS, lenPS);
	memset(data + 2 + lenPS, 0x00, 1);
	memcpy(data + 2 + lenPS + 1, T, lenT);

	if(mod_d) {
		if(mod_s) {
			printHex("HASH(SHA1)", hash, SHA_DIGEST_LENGTH);
			printHex("ID(SHA1)", EMSASHAID, sizeof(EMSASHAID));
		} else {
			printHex("HASH(SHA512)", hash, SHA512_DIGEST_LENGTH);
			printHex("ID(SHA512)", EMSASHA512ID, sizeof(EMSASHA512ID));
		}
		printHex("T", T, getTlength());
		printHex("PS", PS, getPSlength());
		printHex("Data", data, 4096/8);
	}

	free(hash);
	free(T);
	free(PS);

	return data;
}

RSA *createRSA(char *name, int public)
{
	FILE *fp = fopen(name, "rb");

	if(fp == NULL)
		errx(1, "Unable to open %s", name);

	RSA *rsa = RSA_new();

	if(public)
		rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
	else
		rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);

	fclose(fp);

	if(rsa == NULL)
		errx(1, "Invalid RSA Key");

	return rsa;
}

unsigned char *private_encrypt(unsigned char *data, RSA *rsa)
{
	int result;
	unsigned char *enc_data;

	if(mod_d)
		fprintf(stderr, "Private Key Size: %d\n\n", RSA_size(rsa));

	enc_data = malloc(RSA_size(rsa));
	result = RSA_private_encrypt(RSA_size(rsa), data, enc_data, rsa, padding);
	RSA_free(rsa);

	if(result == -1)
		errx(1, "Private Encrypt failed");

	return enc_data;
}

unsigned char *public_decrypt(unsigned char *enc_data, RSA *rsa)
{
	int result;
	unsigned char *dec_data;

	if(mod_d)
		fprintf(stderr, "Public Key Size: %d\n\n", RSA_size(rsa));

	dec_data = malloc(RSA_size(rsa));
	result = RSA_public_decrypt(RSA_size(rsa), enc_data, dec_data, rsa, padding);
	RSA_free(rsa);

	if(result == -1)
		errx(1, "Public Decrypt failed");

	return dec_data;
}

char *readSignature(char *name)
{
	char aux[1024], buf[8192], *b64;
	FILE *fd;

	if((fd = fopen(name, "r")) == NULL)
		errx(1, "Unable to open signature file");

	fgets(aux, sizeof(aux), fd);
	while(fgets(aux, sizeof(aux), fd) != NULL)
		if(strcmp(aux, "---END SRO SIGNATURE---\n") != 0)
			strcat(buf, aux);

	b64 = malloc(strlen(buf));
	memcpy(b64, buf, strlen(buf));

	fclose(fd);

	return b64;
}

char *toBase64(unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

unsigned char *fromBase64(char *input)
{
	BIO *b64, *bmem;
	int length = strlen(input);

	unsigned char *buff = malloc(length);
	memset(buff, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_read(bmem, buff, length);

	BIO_free_all(bmem);

	return buff;
}

int main(int argc, char *argv[])
{
	unsigned char *data, *enc_data, *dec_data;
	RSA *rsa;
	char *b64, *usage = "Usage: sign [-s] [-d] [-v signfile] datafile keyfile";
	int i;

	if(argc > 7 || argc < 3)
		errx(1, "%s", usage);

	for(i = 1; i < argc - 2; ++i) {
		if(strcmp(argv[i], "-s") == 0)
			if(mod_s)
				errx(1, "%s", usage);
			else
				mod_s = 1;
		else if(strcmp(argv[i], "-d") == 0)
			if(mod_d)
				errx(1, "%s", usage);
			else
				mod_d = 1;
		else if(strcmp(argv[i], "-v") == 0)
			if(mod_v)
				errx(1, "%s", usage);
			else {
				mod_v = 1;
				i++;
				b64 = readSignature(argv[i]);
			}
		else
			errx(1, "%s", usage);
	}

	if(mod_d) {
		fprintf(stderr, "mod_v = %d, mod_d = %d, mod_s = %d\n", mod_v, mod_d, mod_s);
		fprintf(stderr, "datafile = %s, keyfile = %s\n\n", argv[i], argv[i + 1]);
	}

	data = doData(argv[i]);
	rsa = createRSA(argv[i + 1], mod_v);

	if(mod_v) {
		enc_data = fromBase64(b64);
		dec_data = public_decrypt(enc_data, rsa);

		if(mod_d) {
			printHex("Encrypted Data", enc_data, 512);
			printHex("Decrypted Data", dec_data, 512);
		}

		if(memcmp(data, dec_data, 512) != 0)
			errx(1, "Firma incorrecta");

		free(dec_data);
	} else {
		enc_data = private_encrypt(data, rsa);
		b64 = toBase64(enc_data, 512);

		if(mod_d)
			printHex("Encrypted Data", enc_data, 512);

		printf("---BEGIN SRO SIGNATURE---\n");
		printf("%s", b64);
		printf("\n---END SRO SIGNATURE---\n");
	}

	free(data);
	free(enc_data);
	free(b64);
	exit(0);
}