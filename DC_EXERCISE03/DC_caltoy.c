#include <stdio.h>
#include "DC_caltoy.h"

typedef uint32_t key_t;

typedef struct cipher {
	ct_t c;
	ct_t cp;
} CTPAIR;

void DDTPrint(void);

int main()
{
	unsigned char max, count, i;
	CTPAIR guessedCipher[100] = { 0 };

	unsigned char gsskey[16] = { 0 };
	pt_t p = 0x0000;
	ct_t c, cp;

	// make DD-Table
	DDTPrint();

	// Filtering
	// from 0 to 0xffff, test if deltaC is [0000 ???? 0000 0000]_2
	count = 0;
	for (p = 0; p <= 0xffff; p++) {
		caltoy_enc(&c, p);
		caltoy_enc(&cp, p ^ 0x00c0);

		// save second nibble of C and C'
		if (!((c ^ cp) & 0xf0ff)) {
			guessedCipher[count].c = c >> 8;
			guessedCipher[count].cp = cp >> 8;

			count++;
		}
	}

	printf("count : %d\n", count);

	// max : the number of pair filtered
	max = count;

	// test each key and find right key
	for (count = 0; count < 16; count++) {
		for (i = 0; i < max; i++) {
			c = guessedCipher[i].c;
			cp = guessedCipher[i].cp;

			// XOR key to C and C'
			c ^= count;
			cp ^= count;

			if ((caltoy_inv_sbox[c] ^ caltoy_inv_sbox[cp]) == 0xc) {
				gsskey[count]++;
			}
		}
	}

	max = 0;
	for (i = 0; i < 16; i++) {
		if (gsskey[max] <= gsskey[i]) {
			max = i;
		}
	}

	printf("key : %d\n", max);

	return 0;
}

// make Differential Distribution Table (DD-t)
void DDTPrint(void) {
	size_t i, j;

	unsigned char DDT[16][16] = { 0 };

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			DDT[i ^ j][caltoy_sbox[i] ^ caltoy_sbox[j]]++;
		}
	}

	printf("Make DDT Table\n");
	printf("+--+-------------------------------------------------+\n");
	printf("|  |  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 |\n");
	printf("+--+-------------------------------------------------+\n");

	for (i = 0; i < 16; i++) {
		printf("|%2d| ", i);

		for (j = 0; j < 16; j++) {
			printf("%2d ", DDT[i][j]);
		}

		printf("|\n");
	}
	printf("+--+-------------------------------------------------+\n");
}
