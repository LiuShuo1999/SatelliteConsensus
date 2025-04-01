#ifndef CONFIG_H
#define CONFIG_H
#include "hotstuff.h"

//crypto
extern char public_key_string[13][192];
extern char private_key_string[13][96];

extern uint8_t private_key[13+1][32];
extern uint8_t public_key[13+1][64];

int sign_FP(FP_BN254 *x);
void hash_sign_struct(char hash[], struct sign_struct *obj);
void hash_sign_struct2(char hash[], struct sign_struct2 *obj);
void hash2point(ECP_BN254 *point, char str[]);
int Sixteen2Ten(char ch);
void init_public_key();


#endif /* config.h */