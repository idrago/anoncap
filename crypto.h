#ifndef CRYPTO_H
#define CRYPTO_H

#include <arpa/inet.h>

void initialize_crypto(char *basenamedir);
uint32_t encrypt_ip(uint32_t orig_addr);
struct in6_addr encrypt_ipv6(struct in6_addr *orig_addr);

#endif
