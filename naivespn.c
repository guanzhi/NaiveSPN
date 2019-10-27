#include <stdio.h>
#include "naivespn.h"


static const unsigned char S[16] = {
	0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7,
};

static const unsigned char SInv[16] = {
	0xE,0x3,0x4,0x8,0x1,0xC,0xA,0xF,0x7,0xD,0x9,0x6,0xB,0x2,0x0,0x5,
};

void naivespn_set_encrypt_key(NAIVESPN_KEY *key,
	const unsigned short rk[NAIVESPN_ROUNDS + 1])
{
	int i;
	for (i = 0; i < NAIVESPN_ROUNDS + 1; i++) {
		key->rk[i] = rk[i];
	}
}

void naivespn_set_decrypt_key(NAIVESPN_KEY *key,
	const unsigned short rk[NAIVESPN_ROUNDS + 1])
{
	int i;
	for (i = 0; i < NAIVESPN_ROUNDS + 1; i++) {
		key->rk[i] = rk[NAIVESPN_ROUNDS - i];
	}
}

unsigned short naivespn_encrypt(unsigned short m, const NAIVESPN_KEY *key)
{
	unsigned short s = m;
	int i;

	for (i = 0; i < NAIVESPN_ROUNDS; i++) {
		unsigned int x0, x1, x2, x3;

		/* subkey mixing */
		s ^= key->rk[i];

		/* subsititution */
		x0 = S[s & 0xf];
		x1 = S[(s >> 4) & 0xf];
		x2 = S[(s >> 8) & 0xf];
		x3 = S[(s >> 12) & 0xf];
		s = x0 | (x1 << 4) | (x2 << 8) | (x3 << 12);

		/* permutation (except final round) */
		if (i != NAIVESPN_ROUNDS - 1) {
			unsigned short t = 0;
			t |= s & 1;
			t |= ((s >>  4) & 1) << 1;
			t |= ((s >>  8) & 1) << 2;
			t |= ((s >> 12) & 1) << 3;
			t |= ((s >>  1) & 1) << 4;
			t |= ((s >>  5) & 1) << 5;
			t |= ((s >>  9) & 1) << 6;
			t |= ((s >> 13) & 1) << 7;
			t |= ((s >>  2) & 1) << 8;
			t |= ((s >>  6) & 1) << 9;
			t |= ((s >> 10) & 1) << 10;
			t |= ((s >> 14) & 1) << 11;
			t |= ((s >>  3) & 1) << 12;
			t |= ((s >>  7) & 1) << 13;
			t |= ((s >> 11) & 1) << 14;
			t |= ((s >> 15) & 1) << 15;
			s = t;
		}
	}

	/* final subkey mixing */
	s ^= key->rk[i];

	return s;
}

unsigned short naivespn_decrypt(unsigned short c, const NAIVESPN_KEY *key)
{
	unsigned short s = c;
	int i;

	s ^= key->rk[0];

	for (i = 1; i < NAIVESPN_ROUNDS + 1; i++) {
		unsigned int x0, x1, x2, x3;

		/* permutation */
		if (i > 1) {
			unsigned short t = 0;
			t |= s & 1;
			t |= ((s >>  4) & 1) << 1;
			t |= ((s >>  8) & 1) << 2;
			t |= ((s >> 12) & 1) << 3;
			t |= ((s >>  1) & 1) << 4;
			t |= ((s >>  5) & 1) << 5;
			t |= ((s >>  9) & 1) << 6;
			t |= ((s >> 13) & 1) << 7;
			t |= ((s >>  2) & 1) << 8;
			t |= ((s >>  6) & 1) << 9;
			t |= ((s >> 10) & 1) << 10;
			t |= ((s >> 14) & 1) << 11;
			t |= ((s >>  3) & 1) << 12;
			t |= ((s >>  7) & 1) << 13;
			t |= ((s >> 11) & 1) << 14;
			t |= ((s >> 15) & 1) << 15;
			s = t;
		}

		/* substitution */
		x0 = SInv[s & 0xf];
		x1 = SInv[(s >> 4) & 0xf];
		x2 = SInv[(s >> 8) & 0xf];
		x3 = SInv[(s >> 12) & 0xf];
		s = x0 | (x1 << 4) | (x2 << 8) | (x3 << 12);

		/* subkey mixing */
		s ^= key->rk[i];
	}

	return s;
}
