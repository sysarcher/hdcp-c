#ifndef __BITSLICE_H__
#define __BITSLICE_H__

#include <inttypes.h>
#include <string.h>

typedef uint64_t bsvec_t;

#define BSBITS (8*sizeof(bsvec_t))

/* Compute the transpose of a slen x 64 bit matrix stored in src */
static inline void BitSlice(int slen, bsvec_t *src, int dlen, bsvec_t *dst)
{
  int i, j, k, m;
  bsvec_t a, t[BSBITS];
  static const bsvec_t mask[6] = {
    UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0xcccccccccccccccc), UINT64_C(0xf0f0f0f0f0f0f0f0),  
    UINT64_C(0xff00ff00ff00ff00), UINT64_C(0xffff0000ffff0000), UINT64_C(0xffffffff00000000)
  };

  memset(t, 0, sizeof(t));
  memcpy(t, src, slen*sizeof(bsvec_t));

  m = 0;
  for (i = 1; i < BSBITS; i <<= 1) {
    for (j = 0; j < BSBITS; j += 2*i) {
      for (k = 0; k < i; k++) {
	a = (t[j + k] ^ (t[j + i + k] << i)) & mask[m];
	t[j + k] ^= a;
	t[j + i + k] ^= a >> i;
      }
    }
    m++;
  }

  memcpy(dst, t, dlen*sizeof(bsvec_t));
}

static inline void BS_print(int dlen, int which, bsvec_t *data)
{
  bsvec_t bsd[BSBITS];
  BitSlice(dlen, data, which + 1, bsd);
  printf("%0*" PRIx64, (dlen + 3) / 4, bsd[which]);
}

#include "bitslice-autogen.h"

#endif /* __BITSLICE_H__ */
