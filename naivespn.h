/*
 * Implementation of Naive SPN Cipher from
 * "A Tutorial on Linear and Differential Cryptanalysis" by Howard M. Heys.
 *
 */
#ifndef NAIVESPN_H
#define NAIVESPN_H

#ifdef __cplusplus
extern "C" {
#endif

#define NAIVESPN_ROUNDS		4

typedef struct {
	unsigned short rk[NAIVESPN_ROUNDS + 1];
} NAIVESPN_KEY;

void naivespn_set_encrypt_key(NAIVESPN_KEY *key, const unsigned short rk[NAIVESPN_ROUNDS + 1]);
void naivespn_set_decrypt_key(NAIVESPN_KEY *key, const unsigned short rk[NAIVESPN_ROUNDS + 1]);
unsigned short naivespn_encrypt(unsigned short m, const NAIVESPN_KEY *key);
unsigned short naivespn_decrypt(unsigned short c, const NAIVESPN_KEY *key);


#ifdef __cplusplus
}
#endif
#endif
