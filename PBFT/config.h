#ifndef CONFIG_H
#define CONFIG_H
#include "PBFT.h"
//crypto

int Sixteen2Ten(char ch);
void init_public_key();
void hash_sign_struct(char *hash, struct sign_struct *obj);

#endif /* config.h */