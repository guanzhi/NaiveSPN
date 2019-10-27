#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "naivespn.h"

int main(void)
{
	NAIVESPN_KEY key;
	unsigned short rk[5] = {0x1234,0x5678,0xabcd,0xef12,0x3456};
	unsigned short m = 0x492E;
	unsigned short c;

	printf("m = %04x\n", m);

	naivespn_set_encrypt_key(&key, rk);
	c = naivespn_encrypt(m, &key);
	printf("c = %04x\n", c);

	naivespn_set_decrypt_key(&key, rk);
	m = naivespn_decrypt(c, &key);
	printf("m = %04x\n", m);

	return 0;
}
