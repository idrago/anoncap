#include <stdio.h>
#include <string.h>

#include <time.h>
#include <stdlib.h>

#include "panon.h"
#include "crypto.h"
#include "base64.h"

#define KEY_SIZE 32

void encrypt_init(char *key, int keysize)
{
	char cryptopan_key[KEY_SIZE];

	memset(cryptopan_key, 0, sizeof(cryptopan_key));
	memcpy(cryptopan_key, key, keysize < sizeof(cryptopan_key) ? keysize : sizeof(cryptopan_key));
	panon_init(cryptopan_key);
}

void initialize_crypto(char *basenamedir)
{
	FILE *fp;
	char *key;
	char *keyfile;
	char *enc_key;
	int flen;

	key = (char*)malloc(sizeof(char) * KEY_SIZE);
	memset(key, 0, KEY_SIZE * sizeof(char));

	fp = fopen("/dev/random", "r");
	if (fp == NULL)
		exit(1);
	if (fread(key, 1, KEY_SIZE, fp) != KEY_SIZE)
		exit(1);
	fclose(fp);

	encrypt_init(key, KEY_SIZE);

	keyfile = (char*)malloc(strlen(basenamedir) + strlen("/CPanKey_") + 2);
	strcpy(keyfile, basenamedir);
	strcat(keyfile, "/CPanKey.key");

	enc_key = base64(key, KEY_SIZE, &flen);

	fp = fopen(keyfile, "w");
	if (fp != NULL)
		fprintf(fp, "%s\n", enc_key);
	else
		fprintf(stderr, "Error opening %s. CPan key not stored\n", keyfile);
	fclose(fp);

	free(enc_key);
	free(keyfile);
}

uint32_t encrypt_ip(uint32_t orig_addr)
{
	return cpp_anonymize(orig_addr);
}

struct in6_addr encrypt_ipv6(struct in6_addr *orig_addr)
{
	struct in6_addr enc_addr;
	enc_addr.s6_addr32[0] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[0])));
	enc_addr.s6_addr32[1] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[1])));
	enc_addr.s6_addr32[2] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[2])));
	enc_addr.s6_addr32[3] = htonl(encrypt_ip(htonl(orig_addr->s6_addr32[3])));
	return enc_addr;
}

