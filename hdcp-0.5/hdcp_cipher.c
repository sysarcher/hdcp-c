/************************************************************
 * A bit-sliced implementation of the HDCP authentication protocol.
 *
 * This software is released under the FreeBSD license.
 * Copyright Rob Johnson and Mikhail Rubnich.
 ************************************************************/

#define __STDC_FORMAT_MACROS /* Get the PRI* macros */

#include <stdio.h>
#include <string.h>
#include "hdcp_cipher.h"
#include "bitslice.h"

#define BS_LFSRBit(r,i) ((r)->state[((r)->zero + i) % (r)->len])

#define BS_LFSRMTap(m,i,j) (BS_LFSRBit(&(m)->lfsrs[i], (m)->lfsrs[i].taps[j]))

void BS_LFSR(BS_LFSReg * r)
{
  bsvec_t newbit;
  int i;
  
  newbit = 0;
  for (i = 0; i < 6 && r->feedbacks[i] >= 0; i++)
    newbit ^= BS_LFSRBit(r, r->feedbacks[i]);

  r->zero--;
  if (r->zero < 0)
    r->zero = r->len - 1;
  BS_LFSRBit(r, 0) = newbit;
}

bsvec_t BS_ShuffleNetwork(bsvec_t *A, bsvec_t *B, 
			   bsvec_t D, bsvec_t S)
{
  bsvec_t result, oldA;
  result = ((~S) & *A) | (S & *B);
  oldA = *A;
  *A = ((~S) & *B) | (S & D);
  *B = ((~S) & D) | (S & oldA);
  return result;
}

void BS_LFSRModule_print(BS_LFSRModule *m, int which)
{
  bsvec_t reg;
  int i, j;

  for (i = 0; i < 4; i++) {
    reg = 0;
    for (j = 0; j < m->lfsrs[i].len; j++)
      reg |= ((BS_LFSRBit(&m->lfsrs[i], j) & (UINT64_C(1) << which)) ? UINT64_C(1) : UINT64_C(0)) << j;
    printf("%0*" PRIx64 " ", (m->lfsrs[i].len + 3) / 4, reg);
  }
  for (i = 0; i < 4; i++)
    printf("%1" PRIx64 "%1" PRIx64 " ", (m->snA[i] >> which) & UINT64_C(1), (m->snB[i] >> which) & UINT64_C(1));
}

void BS_LFSRModule_init(BS_LFSRModule *m, bsvec_t input[56])
{
  int i;

  memset(m, 0, sizeof(*m));
  memset(m->snB, 0xff, sizeof(m->snB));

  m->lfsrs[0] = (BS_LFSReg) { { 3, 7, 12},             /* taps */
			      { 4, 8, 10, 12, -1 },    /* feedbacks */
			      0,                       /* zero */
			      13,                      /* len */
			      { 0 }                    /* state */ 
  };
  m->lfsrs[1] = (BS_LFSReg) { { 4, 8, 13},             /* taps */
			      { 3, 5, 6, 9, 10, 13},   /* feedbacks */
			      0,                       /* zero */
			      14,                      /* len */
			      { 0 }                    /* state */ 
  };
  m->lfsrs[2] = (BS_LFSReg) { { 5, 9, 15},             /* taps */
			      { 4, 6, 7, 11, 14, 15},  /* feedbacks */
			      0,                       /* zero */
			      16,                      /* len */
			      { 0 }                    /* state */ 
  };
  m->lfsrs[3] = (BS_LFSReg) { { 5, 11, 16},            /* taps */
			      { 4, 10, 14, 16, -1},    /* feedbacks */
			      0,                       /* zero */
			      17,                      /* len */
			      { 0 }                    /* state */ 
  };

  for (i = 0; i < 12; i++)
    BS_LFSRBit(&m->lfsrs[0], i) = input[i];
  BS_LFSRBit(&m->lfsrs[0], 12) = ~input[6];

  for (i = 0; i < 13; i++)
    BS_LFSRBit(&m->lfsrs[1], i) = input[i+12];
  BS_LFSRBit(&m->lfsrs[1], 13) = ~input[18];
  
  for (i = 0; i < 15; i++)
    BS_LFSRBit(&m->lfsrs[2], i) = input[i+25];
  BS_LFSRBit(&m->lfsrs[2], 15) = ~input[32];

  for (i = 0; i < 16; i++)
    BS_LFSRBit(&m->lfsrs[3], i) = input[i+40];
  BS_LFSRBit(&m->lfsrs[3], 16) = ~input[47];
}

bsvec_t BS_LFSRModule_clock(BS_LFSRModule * m)
{
  bsvec_t D;
  int i;

  D = 0;
  for (i = 0; i < 4; i++)
    D ^= BS_LFSRMTap(m, i, 0);

  for (i = 0; i < 4; i++)
    D = BS_ShuffleNetwork(&m->snA[i], &m->snB[i], D, BS_LFSRMTap(m, i, 1));

  for (i = 0; i < 4; i++)
    D ^= BS_LFSRMTap(m, i, 2);

  for (i = 0; i < 4; i++)
    BS_LFSR(&m->lfsrs[i]);

  return D;
}

/* A slow and easy-to-read version */
#define KI(i,j) (Kzmap[i][j] ? Kz[KImap[i][j]] : Ky[KImap[i][j]])
#define KO(i,j) (*(j == 0 || j > 4 ? &Kx[KOmap[i][j]] : &Ky[KOmap[i][j]]))

void    BS_DiffuseNetworkK_ (bsvec_t Kz[28], bsvec_t Ky[28], bsvec_t Kx[28])
{
  static const char Kzmap[7][8] = { { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1}
  };
  static const unsigned char KImap[7][8] = { {  0,  7, 10, 13, 16, 16, 20, 24},
					     {  1,  8, 11, 14, 17, 17, 21, 25},
					     {  2,  9, 12, 15, 18, 18, 22, 26},
					     {  3,  0,  3,  6,  9, 19, 23, 27},
					     {  4,  1,  4,  7, 10, 19, 22, 25},
					     {  5,  2,  5,  8, 11, 20, 23, 26},
					     {  6, 12, 13, 14, 15, 21, 24, 27}
  };
  static const unsigned char KOmap[7][8] = { {  0,  0,  1,  2,  3,  1,  2,  3},
					     {  4,  4,  5,  6,  7,  5,  6,  7},
					     {  8,  8,  9, 10, 11,  9, 10, 11},
					     { 12, 12, 13, 14, 15, 13, 14, 15},
					     { 16, 16, 17, 18, 19, 17, 18, 19},
					     { 20, 20, 21, 22, 23, 21, 22, 23},
					     { 24, 24, 25, 26, 27, 25, 26, 27}
  };
  bsvec_t I[7][8], O[7][8];
  int i, j;

  for (i = 0; i < 7; i++)
    for (j = 0; j < 8; j++)
      I[i][j] = KI(i,j);

  for (j = 0; j < 8; j++) {
    O[6][j] = I[0][j];
    for (i = 1; i < 7; i++) 
      O[6][j] ^= I[i][j];
  }
  
  for (i = 0; i < 6; i++)
    for (j = 0; j < 8; j++)
      KO(i,j) = O[6][j] ^ I[i][j];

  for (j = 0; j < 8; j++)
    KO(6,j) = O[6][j];

}

//#define KI(i,j) (Kzmap[i][j] ? Kz[KImap[i][j]] : Ky[KImap[i][j]])
//#define KO(i,j) (*(j == 0 || j > 4 ? &Kx[KOmap[i][j]] : &Ky[KOmap[i][j]]))

void    BS_DiffuseNetworkK_print (void)
{
  static const char Kzmap[7][8] = { { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1}
  };
  static const unsigned char KImap[7][8] = { {  0,  7, 10, 13, 16, 16, 20, 24},
					     {  1,  8, 11, 14, 17, 17, 21, 25},
					     {  2,  9, 12, 15, 18, 18, 22, 26},
					     {  3,  0,  3,  6,  9, 19, 23, 27},
					     {  4,  1,  4,  7, 10, 19, 22, 25},
					     {  5,  2,  5,  8, 11, 20, 23, 26},
					     {  6, 12, 13, 14, 15, 21, 24, 27}
  };
  static const unsigned char KOmap[7][8] = { {  0,  0,  1,  2,  3,  1,  2,  3},
					     {  4,  4,  5,  6,  7,  5,  6,  7},
					     {  8,  8,  9, 10, 11,  9, 10, 11},
					     { 12, 12, 13, 14, 15, 13, 14, 15},
					     { 16, 16, 17, 18, 19, 17, 18, 19},
					     { 20, 20, 21, 22, 23, 21, 22, 23},
					     { 24, 24, 25, 26, 27, 25, 26, 27}
  };
  int i, j;

  printf("/* Auto-generated by BS_DiffuseNetworkK_print */\n"
         "void    BS_DiffuseNetworkK (bsvec_t Kz[28], bsvec_t Ky[28], bsvec_t Kx[28])\n"
         "{\n"
         "bsvec_t I[7][8], O[7][8];\n"
         "\n");


  for (i = 0; i < 7; i++)
    for (j = 0; j < 8; j++)
      printf("  I[%d][%d] = %s[%d];\n", i, j, Kzmap[i][j] ? "Kz" : "Ky", KImap[i][j]);
  printf("\n");

  for (j = 0; j < 8; j++) {
    printf("  O[6][%d] = I[0][%d];\n", j, j);
    for (i = 1; i < 7; i++) 
      printf("  O[6][%d] ^= I[%d][%d];\n", j, i, j);
  }
  printf("\n");
  
  for (i = 0; i < 6; i++)
    for (j = 0; j < 8; j++)
      printf("  %s[%d] = O[6][%d] ^ I[%d][%d];\n", j == 0 || j > 4 ? "Kx" : "Ky", KOmap[i][j], j, i, j);
  printf("\n");

  for (j = 0; j < 8; j++)
    printf("  %s[%d] = O[6][%d];\n", j == 0 || j > 4 ? "Kx" : "Ky", KOmap[6][j], j);
  printf("\n");

  printf("}\n");
}

/* Auto-generated */
void    BS_DiffuseNetworkK (bsvec_t Kz[28], bsvec_t Ky[28], bsvec_t Kx[28])
{
bsvec_t I[7][8], O[7][8];

  I[0][0] = Kz[0];
  I[0][1] = Kz[7];
  I[0][2] = Kz[10];
  I[0][3] = Kz[13];
  I[0][4] = Kz[16];
  I[0][5] = Ky[16];
  I[0][6] = Ky[20];
  I[0][7] = Ky[24];
  I[1][0] = Kz[1];
  I[1][1] = Kz[8];
  I[1][2] = Kz[11];
  I[1][3] = Kz[14];
  I[1][4] = Kz[17];
  I[1][5] = Ky[17];
  I[1][6] = Ky[21];
  I[1][7] = Ky[25];
  I[2][0] = Kz[2];
  I[2][1] = Kz[9];
  I[2][2] = Kz[12];
  I[2][3] = Kz[15];
  I[2][4] = Kz[18];
  I[2][5] = Ky[18];
  I[2][6] = Ky[22];
  I[2][7] = Ky[26];
  I[3][0] = Kz[3];
  I[3][1] = Ky[0];
  I[3][2] = Ky[3];
  I[3][3] = Ky[6];
  I[3][4] = Ky[9];
  I[3][5] = Ky[19];
  I[3][6] = Ky[23];
  I[3][7] = Ky[27];
  I[4][0] = Kz[4];
  I[4][1] = Ky[1];
  I[4][2] = Ky[4];
  I[4][3] = Ky[7];
  I[4][4] = Ky[10];
  I[4][5] = Kz[19];
  I[4][6] = Kz[22];
  I[4][7] = Kz[25];
  I[5][0] = Kz[5];
  I[5][1] = Ky[2];
  I[5][2] = Ky[5];
  I[5][3] = Ky[8];
  I[5][4] = Ky[11];
  I[5][5] = Kz[20];
  I[5][6] = Kz[23];
  I[5][7] = Kz[26];
  I[6][0] = Kz[6];
  I[6][1] = Ky[12];
  I[6][2] = Ky[13];
  I[6][3] = Ky[14];
  I[6][4] = Ky[15];
  I[6][5] = Kz[21];
  I[6][6] = Kz[24];
  I[6][7] = Kz[27];

  O[6][0] = I[0][0];
  O[6][0] ^= I[1][0];
  O[6][0] ^= I[2][0];
  O[6][0] ^= I[3][0];
  O[6][0] ^= I[4][0];
  O[6][0] ^= I[5][0];
  O[6][0] ^= I[6][0];
  O[6][1] = I[0][1];
  O[6][1] ^= I[1][1];
  O[6][1] ^= I[2][1];
  O[6][1] ^= I[3][1];
  O[6][1] ^= I[4][1];
  O[6][1] ^= I[5][1];
  O[6][1] ^= I[6][1];
  O[6][2] = I[0][2];
  O[6][2] ^= I[1][2];
  O[6][2] ^= I[2][2];
  O[6][2] ^= I[3][2];
  O[6][2] ^= I[4][2];
  O[6][2] ^= I[5][2];
  O[6][2] ^= I[6][2];
  O[6][3] = I[0][3];
  O[6][3] ^= I[1][3];
  O[6][3] ^= I[2][3];
  O[6][3] ^= I[3][3];
  O[6][3] ^= I[4][3];
  O[6][3] ^= I[5][3];
  O[6][3] ^= I[6][3];
  O[6][4] = I[0][4];
  O[6][4] ^= I[1][4];
  O[6][4] ^= I[2][4];
  O[6][4] ^= I[3][4];
  O[6][4] ^= I[4][4];
  O[6][4] ^= I[5][4];
  O[6][4] ^= I[6][4];
  O[6][5] = I[0][5];
  O[6][5] ^= I[1][5];
  O[6][5] ^= I[2][5];
  O[6][5] ^= I[3][5];
  O[6][5] ^= I[4][5];
  O[6][5] ^= I[5][5];
  O[6][5] ^= I[6][5];
  O[6][6] = I[0][6];
  O[6][6] ^= I[1][6];
  O[6][6] ^= I[2][6];
  O[6][6] ^= I[3][6];
  O[6][6] ^= I[4][6];
  O[6][6] ^= I[5][6];
  O[6][6] ^= I[6][6];
  O[6][7] = I[0][7];
  O[6][7] ^= I[1][7];
  O[6][7] ^= I[2][7];
  O[6][7] ^= I[3][7];
  O[6][7] ^= I[4][7];
  O[6][7] ^= I[5][7];
  O[6][7] ^= I[6][7];

  Kx[0] = O[6][0] ^ I[0][0];
  Ky[0] = O[6][1] ^ I[0][1];
  Ky[1] = O[6][2] ^ I[0][2];
  Ky[2] = O[6][3] ^ I[0][3];
  Ky[3] = O[6][4] ^ I[0][4];
  Kx[1] = O[6][5] ^ I[0][5];
  Kx[2] = O[6][6] ^ I[0][6];
  Kx[3] = O[6][7] ^ I[0][7];
  Kx[4] = O[6][0] ^ I[1][0];
  Ky[4] = O[6][1] ^ I[1][1];
  Ky[5] = O[6][2] ^ I[1][2];
  Ky[6] = O[6][3] ^ I[1][3];
  Ky[7] = O[6][4] ^ I[1][4];
  Kx[5] = O[6][5] ^ I[1][5];
  Kx[6] = O[6][6] ^ I[1][6];
  Kx[7] = O[6][7] ^ I[1][7];
  Kx[8] = O[6][0] ^ I[2][0];
  Ky[8] = O[6][1] ^ I[2][1];
  Ky[9] = O[6][2] ^ I[2][2];
  Ky[10] = O[6][3] ^ I[2][3];
  Ky[11] = O[6][4] ^ I[2][4];
  Kx[9] = O[6][5] ^ I[2][5];
  Kx[10] = O[6][6] ^ I[2][6];
  Kx[11] = O[6][7] ^ I[2][7];
  Kx[12] = O[6][0] ^ I[3][0];
  Ky[12] = O[6][1] ^ I[3][1];
  Ky[13] = O[6][2] ^ I[3][2];
  Ky[14] = O[6][3] ^ I[3][3];
  Ky[15] = O[6][4] ^ I[3][4];
  Kx[13] = O[6][5] ^ I[3][5];
  Kx[14] = O[6][6] ^ I[3][6];
  Kx[15] = O[6][7] ^ I[3][7];
  Kx[16] = O[6][0] ^ I[4][0];
  Ky[16] = O[6][1] ^ I[4][1];
  Ky[17] = O[6][2] ^ I[4][2];
  Ky[18] = O[6][3] ^ I[4][3];
  Ky[19] = O[6][4] ^ I[4][4];
  Kx[17] = O[6][5] ^ I[4][5];
  Kx[18] = O[6][6] ^ I[4][6];
  Kx[19] = O[6][7] ^ I[4][7];
  Kx[20] = O[6][0] ^ I[5][0];
  Ky[20] = O[6][1] ^ I[5][1];
  Ky[21] = O[6][2] ^ I[5][2];
  Ky[22] = O[6][3] ^ I[5][3];
  Ky[23] = O[6][4] ^ I[5][4];
  Kx[21] = O[6][5] ^ I[5][5];
  Kx[22] = O[6][6] ^ I[5][6];
  Kx[23] = O[6][7] ^ I[5][7];

  Kx[24] = O[6][0];
  Ky[24] = O[6][1];
  Ky[25] = O[6][2];
  Ky[26] = O[6][3];
  Ky[27] = O[6][4];
  Kx[25] = O[6][5];
  Kx[26] = O[6][6];
  Kx[27] = O[6][7];

}

/* A slow but easy-to-read version */

#define BI(i,j) (Bzmap[i][j] ? Bz[BImap[i][j]] : By[BImap[i][j]])
#define BO(i,j) (*(j == 0 || j > 4 ? &Bx[BOmap[i][j]] : &By[BOmap[i][j]]))
#define BK(i,j) (j == 0 ? Ky[i] : j < 5 ? 0 : Ky[7*(j-4) + i])
void    BS_DiffuseNetworkB_ (bsvec_t Bz[28], bsvec_t By[28], bsvec_t Bx[28], bsvec_t Ky[28])
{
  static const char Bzmap[7][8] = { { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1}
  };
  static const unsigned char BImap[7][8] = { {  0,  7, 10, 13, 16, 16, 20, 24},
					     {  1,  8, 11, 14, 17, 17, 21, 25},
					     {  2,  9, 12, 15, 18, 18, 22, 26},
					     {  3,  0,  3,  6,  9, 19, 23, 27},
					     {  4,  1,  4,  7, 10, 19, 22, 25},
					     {  5,  2,  5,  8, 11, 20, 23, 26},
					     {  6, 12, 13, 14, 15, 21, 24, 27}
  };
  static const unsigned char BOmap[7][8] = { {  0,  0,  1,  2,  3,  1,  2,  3},
					     {  4,  4,  5,  6,  7,  5,  6,  7},
					     {  8,  8,  9, 10, 11,  9, 10, 11},
					     { 12, 12, 13, 14, 15, 13, 14, 15},
					     { 16, 16, 17, 18, 19, 17, 18, 19},
					     { 20, 20, 21, 22, 23, 21, 22, 23},
					     { 24, 24, 25, 26, 27, 25, 26, 27}
  };
  bsvec_t O[8][7];
  int i, j;

  for (j = 0; j < 8; j++)
    for (i = 0; i < 7; i++)
      O[j][i] = BI(i,j);

  for (j = 0; j < 8; j++)
    for (i = 0; i < 6; i++)   
      O[j][6] ^= O[j][i];

  for (j = 0; j < 8; j++)
    for (i = 0; i < 6; i++)
      O[j][i] ^= O[j][6];

  for (j = 0; j < 8; j++)
    for (i = 0; i < 7; i++)
      BO(i,j) = O[j][i] ^ BK(i,j);  
}

/* Faster -- eliminate the conditionals induced by Bzmap */
void    BS_DiffuseNetworkB__ (bsvec_t Bz[28], bsvec_t By[28], bsvec_t Bx[28], bsvec_t Ky[28])
{
  static const unsigned char BImap[7][8] = { {  0,  7, 10, 13, 16, 16, 20, 24},
					     {  1,  8, 11, 14, 17, 17, 21, 25},
					     {  2,  9, 12, 15, 18, 18, 22, 26},
					     {  3,  0,  3,  6,  9, 19, 23, 27},
					     {  4,  1,  4,  7, 10, 19, 22, 25},
					     {  5,  2,  5,  8, 11, 20, 23, 26},
					     {  6, 12, 13, 14, 15, 21, 24, 27}
  };
  static const unsigned char BOmap[7][8] = { {  0,  0,  1,  2,  3,  1,  2,  3},
					     {  4,  4,  5,  6,  7,  5,  6,  7},
					     {  8,  8,  9, 10, 11,  9, 10, 11},
					     { 12, 12, 13, 14, 15, 13, 14, 15},
					     { 16, 16, 17, 18, 19, 17, 18, 19},
					     { 20, 20, 21, 22, 23, 21, 22, 23},
					     { 24, 24, 25, 26, 27, 25, 26, 27}
  };

  bsvec_t O[8][7];
  int i, j;

  for (i = 0; i < 7; i++)
    O[0][i] = Bz[BImap[i][0]];
  for (j = 1; j < 5; j++) {
    for (i = 0; i < 3; i++)
      O[j][i] = Bz[BImap[i][j]];
    for (i = 3; i < 7; i++)
      O[j][i] = By[BImap[i][j]];
  }
  for (j = 5; j < 8; j++) {
    for (i = 0; i < 4; i++)
      O[j][i] = By[BImap[i][j]];
    for (i = 4; i < 7; i++)
      O[j][i] = Bz[BImap[i][j]];
  }

  for (j = 0; j < 8; j++)
    for (i = 0; i < 6; i++)   
      O[j][6] ^= O[j][i];

  for (j = 0; j < 8; j++)
    for (i = 0; i < 6; i++)
      O[j][i] ^= O[j][6];

  //#define BO(i,j) (*(j == 0 || j > 4 ? &Bx[BOmap[i][j]] : &By[BOmap[i][j]]))
  //#define BK(i,j) (j == 0 ? Ky[i] : j < 5 ? 0 : Ky[7*(j-4) + i])
  for (i = 0; i < 7; i++)
    Bx[BOmap[i][0]] = O[0][i] ^ Ky[i];
  for (j = 1; j < 5; j++)
    for (i = 0; i < 7; i++)
      By[BOmap[i][j]] = O[j][i];
  for (j = 5; j < 8; j++)
    for (i = 0; i < 7; i++)
      Bx[BOmap[i][j]] = O[j][i] ^ Ky[7*(j-4)+i];
  /* for (j = 5; j < 8; j++) */
  /*   for (i = 0; i < 7; i++) */
  /*     BO(i,j) = O[j][i] ^ BK(i,j);   */
}

/* An auto-generated completely unrolled one.  This actually generates
   the smallest and fastest code in gcc. */
void    BS_DiffuseNetworkB_print (void)
{
  static const char Bzmap[7][8] = { { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 1, 1, 1, 1, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 0, 0, 0},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1},
				    { 1, 0, 0, 0, 0, 1, 1, 1}
  };
  static const unsigned char BImap[7][8] = { {  0,  7, 10, 13, 16, 16, 20, 24},
					     {  1,  8, 11, 14, 17, 17, 21, 25},
					     {  2,  9, 12, 15, 18, 18, 22, 26},
					     {  3,  0,  3,  6,  9, 19, 23, 27},
					     {  4,  1,  4,  7, 10, 19, 22, 25},
					     {  5,  2,  5,  8, 11, 20, 23, 26},
					     {  6, 12, 13, 14, 15, 21, 24, 27}
  };
  static const unsigned char BOmap[7][8] = { {  0,  0,  1,  2,  3,  1,  2,  3},
					     {  4,  4,  5,  6,  7,  5,  6,  7},
					     {  8,  8,  9, 10, 11,  9, 10, 11},
					     { 12, 12, 13, 14, 15, 13, 14, 15},
					     { 16, 16, 17, 18, 19, 17, 18, 19},
					     { 20, 20, 21, 22, 23, 21, 22, 23},
					     { 24, 24, 25, 26, 27, 25, 26, 27}
  };
  int i, j;

  printf("/* Auto-generated by BS_DiffuseNetworkB_print */\n"
         "void    BS_DiffuseNetworkB (bsvec_t Bz[28], bsvec_t By[28], bsvec_t Bx[28], bsvec_t Ky[28])\n"
         "{\n"
         "  bsvec_t O[8][7];\n"
         "\n");

  for (j = 0; j < 8; j++)
    for (i = 0; i < 7; i++) {
      printf("  O[%d][%d] = ", j, i); //BI(i,j);\n",
      printf("  %s[%d];\n", Bzmap[i][j] ? "Bz" : "By", BImap[i][j]);
    }
  printf("\n");

  for (j = 0; j < 8; j++)
    for (i = 0; i < 6; i++)   
      printf("  O[%d][6] ^= O[%d][%d];\n", j, j, i);
  printf("\n");

  for (j = 0; j < 8; j++)
    for (i = 0; i < 6; i++)
      printf("  O[%d][%d] ^= O[%d][6];\n", j, i, j);
  printf("\n");

  for (j = 0; j < 8; j++)
    for (i = 0; i < 7; i++) {
      printf("  %s[%d] = O[%d][%d]", j == 0 || j > 4 ? "Bx" : "By", BOmap[i][j], j, i);
      if (j == 0 || j >= 5)
        printf("^ Ky[%d]", j == 0 ? i : 7*(j-4) + i);
      printf(";\n");
    }
  printf("}\n");
}

/* Auto-generated */
void    BS_DiffuseNetworkB (bsvec_t Bz[28], bsvec_t By[28], bsvec_t Bx[28], bsvec_t Ky[28])
{
  bsvec_t O[8][7];

  O[0][0] =   Bz[0];
  O[0][1] =   Bz[1];
  O[0][2] =   Bz[2];
  O[0][3] =   Bz[3];
  O[0][4] =   Bz[4];
  O[0][5] =   Bz[5];
  O[0][6] =   Bz[6];
  O[1][0] =   Bz[7];
  O[1][1] =   Bz[8];
  O[1][2] =   Bz[9];
  O[1][3] =   By[0];
  O[1][4] =   By[1];
  O[1][5] =   By[2];
  O[1][6] =   By[12];
  O[2][0] =   Bz[10];
  O[2][1] =   Bz[11];
  O[2][2] =   Bz[12];
  O[2][3] =   By[3];
  O[2][4] =   By[4];
  O[2][5] =   By[5];
  O[2][6] =   By[13];
  O[3][0] =   Bz[13];
  O[3][1] =   Bz[14];
  O[3][2] =   Bz[15];
  O[3][3] =   By[6];
  O[3][4] =   By[7];
  O[3][5] =   By[8];
  O[3][6] =   By[14];
  O[4][0] =   Bz[16];
  O[4][1] =   Bz[17];
  O[4][2] =   Bz[18];
  O[4][3] =   By[9];
  O[4][4] =   By[10];
  O[4][5] =   By[11];
  O[4][6] =   By[15];
  O[5][0] =   By[16];
  O[5][1] =   By[17];
  O[5][2] =   By[18];
  O[5][3] =   By[19];
  O[5][4] =   Bz[19];
  O[5][5] =   Bz[20];
  O[5][6] =   Bz[21];
  O[6][0] =   By[20];
  O[6][1] =   By[21];
  O[6][2] =   By[22];
  O[6][3] =   By[23];
  O[6][4] =   Bz[22];
  O[6][5] =   Bz[23];
  O[6][6] =   Bz[24];
  O[7][0] =   By[24];
  O[7][1] =   By[25];
  O[7][2] =   By[26];
  O[7][3] =   By[27];
  O[7][4] =   Bz[25];
  O[7][5] =   Bz[26];
  O[7][6] =   Bz[27];

  O[0][6] ^= O[0][0];
  O[0][6] ^= O[0][1];
  O[0][6] ^= O[0][2];
  O[0][6] ^= O[0][3];
  O[0][6] ^= O[0][4];
  O[0][6] ^= O[0][5];
  O[1][6] ^= O[1][0];
  O[1][6] ^= O[1][1];
  O[1][6] ^= O[1][2];
  O[1][6] ^= O[1][3];
  O[1][6] ^= O[1][4];
  O[1][6] ^= O[1][5];
  O[2][6] ^= O[2][0];
  O[2][6] ^= O[2][1];
  O[2][6] ^= O[2][2];
  O[2][6] ^= O[2][3];
  O[2][6] ^= O[2][4];
  O[2][6] ^= O[2][5];
  O[3][6] ^= O[3][0];
  O[3][6] ^= O[3][1];
  O[3][6] ^= O[3][2];
  O[3][6] ^= O[3][3];
  O[3][6] ^= O[3][4];
  O[3][6] ^= O[3][5];
  O[4][6] ^= O[4][0];
  O[4][6] ^= O[4][1];
  O[4][6] ^= O[4][2];
  O[4][6] ^= O[4][3];
  O[4][6] ^= O[4][4];
  O[4][6] ^= O[4][5];
  O[5][6] ^= O[5][0];
  O[5][6] ^= O[5][1];
  O[5][6] ^= O[5][2];
  O[5][6] ^= O[5][3];
  O[5][6] ^= O[5][4];
  O[5][6] ^= O[5][5];
  O[6][6] ^= O[6][0];
  O[6][6] ^= O[6][1];
  O[6][6] ^= O[6][2];
  O[6][6] ^= O[6][3];
  O[6][6] ^= O[6][4];
  O[6][6] ^= O[6][5];
  O[7][6] ^= O[7][0];
  O[7][6] ^= O[7][1];
  O[7][6] ^= O[7][2];
  O[7][6] ^= O[7][3];
  O[7][6] ^= O[7][4];
  O[7][6] ^= O[7][5];

  O[0][0] ^= O[0][6];
  O[0][1] ^= O[0][6];
  O[0][2] ^= O[0][6];
  O[0][3] ^= O[0][6];
  O[0][4] ^= O[0][6];
  O[0][5] ^= O[0][6];
  O[1][0] ^= O[1][6];
  O[1][1] ^= O[1][6];
  O[1][2] ^= O[1][6];
  O[1][3] ^= O[1][6];
  O[1][4] ^= O[1][6];
  O[1][5] ^= O[1][6];
  O[2][0] ^= O[2][6];
  O[2][1] ^= O[2][6];
  O[2][2] ^= O[2][6];
  O[2][3] ^= O[2][6];
  O[2][4] ^= O[2][6];
  O[2][5] ^= O[2][6];
  O[3][0] ^= O[3][6];
  O[3][1] ^= O[3][6];
  O[3][2] ^= O[3][6];
  O[3][3] ^= O[3][6];
  O[3][4] ^= O[3][6];
  O[3][5] ^= O[3][6];
  O[4][0] ^= O[4][6];
  O[4][1] ^= O[4][6];
  O[4][2] ^= O[4][6];
  O[4][3] ^= O[4][6];
  O[4][4] ^= O[4][6];
  O[4][5] ^= O[4][6];
  O[5][0] ^= O[5][6];
  O[5][1] ^= O[5][6];
  O[5][2] ^= O[5][6];
  O[5][3] ^= O[5][6];
  O[5][4] ^= O[5][6];
  O[5][5] ^= O[5][6];
  O[6][0] ^= O[6][6];
  O[6][1] ^= O[6][6];
  O[6][2] ^= O[6][6];
  O[6][3] ^= O[6][6];
  O[6][4] ^= O[6][6];
  O[6][5] ^= O[6][6];
  O[7][0] ^= O[7][6];
  O[7][1] ^= O[7][6];
  O[7][2] ^= O[7][6];
  O[7][3] ^= O[7][6];
  O[7][4] ^= O[7][6];
  O[7][5] ^= O[7][6];

  Bx[0] = O[0][0]^ Ky[0];
  Bx[4] = O[0][1]^ Ky[1];
  Bx[8] = O[0][2]^ Ky[2];
  Bx[12] = O[0][3]^ Ky[3];
  Bx[16] = O[0][4]^ Ky[4];
  Bx[20] = O[0][5]^ Ky[5];
  Bx[24] = O[0][6]^ Ky[6];
  By[0] = O[1][0];
  By[4] = O[1][1];
  By[8] = O[1][2];
  By[12] = O[1][3];
  By[16] = O[1][4];
  By[20] = O[1][5];
  By[24] = O[1][6];
  By[1] = O[2][0];
  By[5] = O[2][1];
  By[9] = O[2][2];
  By[13] = O[2][3];
  By[17] = O[2][4];
  By[21] = O[2][5];
  By[25] = O[2][6];
  By[2] = O[3][0];
  By[6] = O[3][1];
  By[10] = O[3][2];
  By[14] = O[3][3];
  By[18] = O[3][4];
  By[22] = O[3][5];
  By[26] = O[3][6];
  By[3] = O[4][0];
  By[7] = O[4][1];
  By[11] = O[4][2];
  By[15] = O[4][3];
  By[19] = O[4][4];
  By[23] = O[4][5];
  By[27] = O[4][6];
  Bx[1] = O[5][0]^ Ky[7];
  Bx[5] = O[5][1]^ Ky[8];
  Bx[9] = O[5][2]^ Ky[9];
  Bx[13] = O[5][3]^ Ky[10];
  Bx[17] = O[5][4]^ Ky[11];
  Bx[21] = O[5][5]^ Ky[12];
  Bx[25] = O[5][6]^ Ky[13];
  Bx[2] = O[6][0]^ Ky[14];
  Bx[6] = O[6][1]^ Ky[15];
  Bx[10] = O[6][2]^ Ky[16];
  Bx[14] = O[6][3]^ Ky[17];
  Bx[18] = O[6][4]^ Ky[18];
  Bx[22] = O[6][5]^ Ky[19];
  Bx[26] = O[6][6]^ Ky[20];
  Bx[3] = O[7][0]^ Ky[21];
  Bx[7] = O[7][1]^ Ky[22];
  Bx[11] = O[7][2]^ Ky[23];
  Bx[15] = O[7][3]^ Ky[24];
  Bx[19] = O[7][4]^ Ky[25];
  Bx[23] = O[7][5]^ Ky[26];
  Bx[27] = O[7][6]^ Ky[27];
}

#define LOADINPUTS(i) D = input[i]; C = input[i + 7]; \
                      B = input[i + 14]; A = input[i + 21];

void BS_SBoxB(bsvec_t input[28], bsvec_t output[28])
{
  bsvec_t A, B, C, D;

  LOADINPUTS(0);
  output[0] = (~A&((C^D) | (B&~C))) | (A&~B&C&D) | (B&(C^D));
  output[7] = (C&((~B&~D) | (A&D))) | (B&D&(C|A)) |(~D&((A&~B)|(~A&B&~C)));
  output[14] = (C&(A^B))|(D&((A&~C)|(~A&B)))|(~A&~B&~C&~D);
  output[21] = (B&((A&D)|(~C&~D))) | (~A&((B&~D)|(~B&~C))) | (A&~B&C&~D);

  LOADINPUTS(1);
  output[1] = (~A&(~(C^D) | (B&~D))) | (A&((~B&C) | (B&~C&D)));
  output[8] = ((~A&C&~D) | (B&~C&D) ) | (~C&((A&B)|(~B&~D))) | (A&~B&C&D);
  output[15] = (A&(B^D))|(B&~C&(A|~D))|(~A&C&~(B^D));
  output[22] = (C&(~D|(~A&B)))|(~B&((A&~D)|(~A&~C&D))) | (A&B&~C&D);

  LOADINPUTS(2);
  output[2] = (~A&~(B^D)) | (A&~B&~C&D) | (B&~(A^C));
  output[9] = ((~A&C&D)|(B&~C&~D))|(~A&~D&(B|~C))|(A&~B&(C^D));
  output[16] = (~C&(~B|(~A&D)))|(A&((~B&~D)|(B&C&D)))|(~A&B&C&~D);
  output[23] = (B&(C^D))|(~C&(A^B))|(~A&~B&C&D);

  LOADINPUTS(3);
  output[3] = (~A&~B&~C&D) | ((A^C)&~D) | (A&~(B^D));
  output[10] = ((~A&B&C)|(A&~C&D))|(~A&~C&(~D|~B))|(A&~B&C&~D);
  output[17] = (B&D&(A|~C))|(~B&~C&(A|~D))|(~A&C&(B^D));
  output[24] = (A&C&(~B|D))|((A&~B&D)|(B&~C&~D)) |(~A&B&(~D|~C));

  LOADINPUTS(4);
  output[4] = (~C&~(B^D)) | ((A^C)&~D) | (A&~B&C&D);
  output[11] = (C&((A&~B)|(B&D)))|(~A&~B&(~D|~C)) | (A&B&~C&~D);
  output[18] = (~B&C&(D|~A)) | (D&~(A^B)) |(~C&~D&(A^B));
  output[25] = (C&~D&(~A|~B))|((~A&~B&C)|(A&~C&D)) |(A&B&(D|~C));

  LOADINPUTS(5);
  output[5] = (~(A^C)&~D) | ((A^C)&B&D) | (~B&((A&C) | (~C&~D)));
  output[12] = ((A&~B&C)|(~A&B&D))|(~A&~B&(~D|~C))|(A&B&~C&~D);
  output[19] = (C&((~B&~D)|(~A&B))) | (~C&D&(A|~B))|(~A&B&~D);
  output[26] = (C&~D&(A|B))|((~A&~B&D)|(A&B&~C))|(~A&~B&~C);

  LOADINPUTS(6);
  output[6] = (~A&~(B^D)) | (A&C&(B^D)) | (~B&((~A&~C) | (~C&~D)));
  output[13] = (A&((B&C)|(~B&D)))|(~C&(B^D))|(~A&~B&C&~D);
  output[20] = (~A&C&(~D|~B))|(A&((~B&D)|(~C&~D))) | (~A&B&~C&D);
  output[27] = (C&((A&D)|(~A&B)))|(A&~D&(~B|~C))|(~A&~B&~C&D);
}

void BS_SBoxK(bsvec_t input[28], bsvec_t output[28])
{
  bsvec_t A, B, C, D;

  LOADINPUTS(0);
  output[0] = (~A&~B&C) | (A&B&D) | (A&~B&(~D | ~C)) | (~A&B&~C&~D);
  output[7] = (A&((C&~D)|(~B&D)))|(~C&D&(A|~B)) | (~A&B&~(C^D));
  output[14] = (C&((~B&~D)|(~A&B))) | (A&B&(D|~C)) | (~A&~B&~C&D);
  output[21] = (C&~D&(A|B)) |((A&B&C) | (~B&~C&D)) | (~A&~B&(D|~C));

  LOADINPUTS(1);
  output[1] = (~A&C&(B | D)) | (B&((~A&D) | (A&~C))) | (~B&~D&~(A^C));
  output[8] = (~A&~B&D) | ((A^D)&~C) | (B&C&(~D | A));
  output[15] = (~A&((~B&(D | C)) | (C&D))) | (~B&C&D) | (A&B&(~C | ~D));
  output[22] = (C&(B^D)) | (~D&(A^B)) | (A&B&~C&D);

  LOADINPUTS(2);
  output[2] = (~C&((~A&(~B|~D)) | (~B&~D))) | (B&((C&D) | (A&(C|D))));
  output[9] = (~A&D&(C|~B)) | (B&((A&~C)|(~A&~D))) | (A&~B&C&~D);
  output[16] = (C&D&(B|~A))|(~A&~C&(B|~D))|(A&~B&(C^D));
  output[23] = (~B&(C^D)) | ( (A&B&~D)|(~A&~B&~C)) | (~A&B&C&D);

  LOADINPUTS(3);
  output[3] = (~B&C&(D | ~A)) | ((~A&B&D) | (A&~C&~D)) | (A&B&~D);
  output[10] = ((~A&C&~D)|(A&B&D)) | (~A&D&(~C|~B)) |(A&~B&~C&~D);
  output[17] = (C&((A&B)|(~A&D)))| (~B&((~A&D)|(A&~C))) | (~A&B&~C&~D);
  output[24] = (~D&((~B&C)|(A&~C))) | (B&~C&(A|~D)) | (~A&D&~(B^C));

  LOADINPUTS(4);
  output[4] = (~(A^B)&~C&D) | ((C | (~A&B))&~D) | (A&~B&C);
  output[11] = (~B&(C^D))|(~C&(A^B)) |(A&B&C&D);
  output[18] = ((~A&B&D)|(~B&~C&~D)) | (~A&~B&(~D|~C)) |(A&C&(B^D));
  output[25] = (~A&(B^C)) | (~(A^D)&~C) | (A&B&C&~D);

  LOADINPUTS(5);
  output[5] = (~A&((~B&~D) | (B&~C&D))) | (A&(~(C^D) | (~B&~C)));
  output[12] = (~B&C&(D|~A)) |(B&D&(~C|~A)) | (A&~D&~(B^C));
  output[19] = (~A&C&(~D|B))|(~B&D&(A|~C)) | (A&B&~C);
  output[26] = (C&D&(A|B))|(A&~D&(~C|B))|(~C&((B&~D)|(~A&~B&D)));

  LOADINPUTS(6);
  output[6] = ((A^C)&B) | (~B&((A&C)^D));
  output[13] = (C&((~A&~D)|(A&~B)))|(~A&~C&(D|~B)) |(A&B&~C&~D);
  output[20] = (~A&D&(B|~C)) | (A&~D&(~C|B)) |( (A&B&~C) | (~A&~B&C&~D));
  output[27] = (B&D&(C|~A)) |(A&~B&(~D|~C)) | (~C&~D&(A|~B));
}

void BS_RoundFunctionK(bsvec_t Kz[28], bsvec_t Ky[28], bsvec_t Kx[28])
{
  bsvec_t newKz[28];
  BS_SBoxK(Kx, newKz);
  BS_DiffuseNetworkK(Kz, Ky, Kx);
  memcpy(Kz, newKz, sizeof(newKz));
}

void BS_RoundFunctionB(bsvec_t Bz[28], bsvec_t By[28], 
		       bsvec_t Bx[28], bsvec_t Ky[28])
{
  bsvec_t newBz[28];
  BS_SBoxB(Bx, newBz);
  BS_DiffuseNetworkB(Bz, By, Bx, Ky);
  memcpy(Bz, newBz, sizeof(newBz));
}

void BS_BlockModule(BS_HDCPBlockModule *bm)
{
  BS_RoundFunctionB(bm->B[2], bm->B[1], bm->B[0], bm->K[1]);
  BS_RoundFunctionK(bm->K[2], bm->K[1], bm->K[0]);
}

/* Easy-to-read version, but slow */
void BS_OutputFunction_(bsvec_t Bz[28], bsvec_t By[28], 
		       bsvec_t Kz[28], bsvec_t Ky[28], 
		       bsvec_t result[24])
{
  const static unsigned char BS_OutputTable[24][16] =
    {
      {17, 26, 22, 27, 21, 18,  2,  5,  3,  6,  0,  9,  4, 22,  5, 10},
      { 5, 20, 15, 24,  2, 25,  0, 16, 20, 18,  7, 23, 15,  5,  3, 25},
      {22,  5, 14, 16, 25, 17, 20, 11,  7, 19,  2, 10, 22,  4, 13, 21},
      {19,  3, 15, 11, 21, 16, 27,  1,  6, 14,  9,  8, 17, 18, 12, 24},
      
      {19,  6, 17, 18, 22,  7,  9, 12, 25,  6,  5,  2, 10, 15, 21,  8},
      { 3,  7,  4,  8, 16,  6,  5, 17, 27, 14,  2,  4, 24, 19,  1, 12},
      { 8, 21, 27,  2, 11, 24, 12,  3, 17, 26,  4, 16, 27,  7, 22, 11},
      { 9,  5,  7,  4,  8, 13,  3, 15,  9, 10, 19, 11,  7,  6,  8, 23},
      
      {26, 13, 23, 10, 11,  7, 15, 19, 13, 12, 18, 24, 15, 23,  7, 16},
      { 1,  0, 19, 11, 13, 16, 24, 18,  0,  5, 20, 25,  1, 24,  9, 27},
      {26, 13,  9, 14, 10,  4,  1,  2, 14, 23, 27, 25, 17, 19,  1, 22},
      {21, 15,  5,  3, 13, 25, 16, 27,  6, 21, 17, 15, 26, 11, 16,  7},
      
      {20,  7, 18, 12, 17,  1, 16,  0, 11, 22, 20,  0, 26, 23, 17,  2},
      {14, 23,  1, 12, 24,  6, 18,  9,  8,  4,  3, 14, 20, 26, 23, 15},
      {19,  6, 21, 25, 23,  1, 10,  8, 19,  0, 18,  2, 13,  8, 24, 14},
      { 3,  0, 27, 23, 19,  8,  4,  7, 16, 21, 24, 25, 12, 27, 15, 18},

      { 6,  5, 14, 22, 24, 18,  2, 21,  3,  5,  8, 25,  7, 27,  2, 26},
      { 3,  4,  2,  6, 22, 14, 12, 26, 11, 14, 23, 17, 22, 13, 19,  4},
      {25, 21, 19,  9, 10, 15, 13, 22,  1, 16, 14, 11, 12,  6, 10, 19},
      {23, 11, 10, 20,  1, 12, 14,  4, 21,  1, 10, 20, 18, 26,  9, 13},
      
      {11, 26, 20, 17,  8, 23,  0, 24, 20, 21,  9, 25, 12,  3, 15,  0},
      { 9, 17, 26,  4, 27,  0, 15,  6, 18, 12, 21, 27,  1, 16, 24, 20},
      {22, 12,  2, 10,  7, 20, 25, 13, 13,  0,  3, 16, 22, 11, 26,  9},
      {27, 24, 26,  8,  0,  9, 18, 23,  2,  0, 13,  5,  4,  8, 10,  3}
    };
  int i, j;

  for (i = 0; i < 24; i++) {
    result[i] = 0;
    for (j = 0; j < 7; j++) {
      result[i] ^= Bz[BS_OutputTable[i][j]] & Kz[BS_OutputTable[i][j+8]];
    }
    result[i] ^= By[BS_OutputTable[i][7]] ^ Ky[BS_OutputTable[i][15]];
  }
}

/* Generate an unrolled version */
void BS_OutputFunction_print(void)
{
  const static unsigned char BS_OutputTable[24][16] =
    {
      {17, 26, 22, 27, 21, 18,  2,  5,  3,  6,  0,  9,  4, 22,  5, 10},
      { 5, 20, 15, 24,  2, 25,  0, 16, 20, 18,  7, 23, 15,  5,  3, 25},
      {22,  5, 14, 16, 25, 17, 20, 11,  7, 19,  2, 10, 22,  4, 13, 21},
      {19,  3, 15, 11, 21, 16, 27,  1,  6, 14,  9,  8, 17, 18, 12, 24},
      
      {19,  6, 17, 18, 22,  7,  9, 12, 25,  6,  5,  2, 10, 15, 21,  8},
      { 3,  7,  4,  8, 16,  6,  5, 17, 27, 14,  2,  4, 24, 19,  1, 12},
      { 8, 21, 27,  2, 11, 24, 12,  3, 17, 26,  4, 16, 27,  7, 22, 11},
      { 9,  5,  7,  4,  8, 13,  3, 15,  9, 10, 19, 11,  7,  6,  8, 23},
      
      {26, 13, 23, 10, 11,  7, 15, 19, 13, 12, 18, 24, 15, 23,  7, 16},
      { 1,  0, 19, 11, 13, 16, 24, 18,  0,  5, 20, 25,  1, 24,  9, 27},
      {26, 13,  9, 14, 10,  4,  1,  2, 14, 23, 27, 25, 17, 19,  1, 22},
      {21, 15,  5,  3, 13, 25, 16, 27,  6, 21, 17, 15, 26, 11, 16,  7},
      
      {20,  7, 18, 12, 17,  1, 16,  0, 11, 22, 20,  0, 26, 23, 17,  2},
      {14, 23,  1, 12, 24,  6, 18,  9,  8,  4,  3, 14, 20, 26, 23, 15},
      {19,  6, 21, 25, 23,  1, 10,  8, 19,  0, 18,  2, 13,  8, 24, 14},
      { 3,  0, 27, 23, 19,  8,  4,  7, 16, 21, 24, 25, 12, 27, 15, 18},

      { 6,  5, 14, 22, 24, 18,  2, 21,  3,  5,  8, 25,  7, 27,  2, 26},
      { 3,  4,  2,  6, 22, 14, 12, 26, 11, 14, 23, 17, 22, 13, 19,  4},
      {25, 21, 19,  9, 10, 15, 13, 22,  1, 16, 14, 11, 12,  6, 10, 19},
      {23, 11, 10, 20,  1, 12, 14,  4, 21,  1, 10, 20, 18, 26,  9, 13},
      
      {11, 26, 20, 17,  8, 23,  0, 24, 20, 21,  9, 25, 12,  3, 15,  0},
      { 9, 17, 26,  4, 27,  0, 15,  6, 18, 12, 21, 27,  1, 16, 24, 20},
      {22, 12,  2, 10,  7, 20, 25, 13, 13,  0,  3, 16, 22, 11, 26,  9},
      {27, 24, 26,  8,  0,  9, 18, 23,  2,  0, 13,  5,  4,  8, 10,  3}
    };
  int i, j;

  printf("/* Auto-generated by BS_OutputFunction_print */\n"
         "void BS_OutputFunction(bsvec_t Bz[28], bsvec_t By[28],\n"
         "                       bsvec_t Kz[28], bsvec_t Ky[28],\n"
         "                       bsvec_t result[24])\n"
         "{\n");

  for (i = 0; i < 24; i++) {
    printf("  result[%d] = (Bz[%d] & Kz[%d])",
           i, BS_OutputTable[i][0], BS_OutputTable[i][8]);
    for (j = 1; j < 7; j++) {
      printf(" ^ (Bz[%d] & Kz[%d])",
             BS_OutputTable[i][j], BS_OutputTable[i][j+8]);
    }
    printf(" ^ (By[%d] ^ Ky[%d]);\n",
           BS_OutputTable[i][7], BS_OutputTable[i][15]);
  }
  printf("}\n");
}

/* Auto-generated by BS_OutputFunction_print */
void BS_OutputFunction(bsvec_t Bz[28], bsvec_t By[28],
                       bsvec_t Kz[28], bsvec_t Ky[28],
                       bsvec_t result[24])
{
  result[0] = (Bz[17] & Kz[3]) ^ (Bz[26] & Kz[6]) ^ (Bz[22] & Kz[0]) ^ (Bz[27] & Kz[9]) ^ (Bz[21] & Kz[4]) ^ (Bz[18] & Kz[22]) ^ (Bz[2] & Kz[5]) ^ (By[5] ^ Ky[10]);
  result[1] = (Bz[5] & Kz[20]) ^ (Bz[20] & Kz[18]) ^ (Bz[15] & Kz[7]) ^ (Bz[24] & Kz[23]) ^ (Bz[2] & Kz[15]) ^ (Bz[25] & Kz[5]) ^ (Bz[0] & Kz[3]) ^ (By[16] ^ Ky[25]);
  result[2] = (Bz[22] & Kz[7]) ^ (Bz[5] & Kz[19]) ^ (Bz[14] & Kz[2]) ^ (Bz[16] & Kz[10]) ^ (Bz[25] & Kz[22]) ^ (Bz[17] & Kz[4]) ^ (Bz[20] & Kz[13]) ^ (By[11] ^ Ky[21]);
  result[3] = (Bz[19] & Kz[6]) ^ (Bz[3] & Kz[14]) ^ (Bz[15] & Kz[9]) ^ (Bz[11] & Kz[8]) ^ (Bz[21] & Kz[17]) ^ (Bz[16] & Kz[18]) ^ (Bz[27] & Kz[12]) ^ (By[1] ^ Ky[24]);
  result[4] = (Bz[19] & Kz[25]) ^ (Bz[6] & Kz[6]) ^ (Bz[17] & Kz[5]) ^ (Bz[18] & Kz[2]) ^ (Bz[22] & Kz[10]) ^ (Bz[7] & Kz[15]) ^ (Bz[9] & Kz[21]) ^ (By[12] ^ Ky[8]);
  result[5] = (Bz[3] & Kz[27]) ^ (Bz[7] & Kz[14]) ^ (Bz[4] & Kz[2]) ^ (Bz[8] & Kz[4]) ^ (Bz[16] & Kz[24]) ^ (Bz[6] & Kz[19]) ^ (Bz[5] & Kz[1]) ^ (By[17] ^ Ky[12]);
  result[6] = (Bz[8] & Kz[17]) ^ (Bz[21] & Kz[26]) ^ (Bz[27] & Kz[4]) ^ (Bz[2] & Kz[16]) ^ (Bz[11] & Kz[27]) ^ (Bz[24] & Kz[7]) ^ (Bz[12] & Kz[22]) ^ (By[3] ^ Ky[11]);
  result[7] = (Bz[9] & Kz[9]) ^ (Bz[5] & Kz[10]) ^ (Bz[7] & Kz[19]) ^ (Bz[4] & Kz[11]) ^ (Bz[8] & Kz[7]) ^ (Bz[13] & Kz[6]) ^ (Bz[3] & Kz[8]) ^ (By[15] ^ Ky[23]);
  result[8] = (Bz[26] & Kz[13]) ^ (Bz[13] & Kz[12]) ^ (Bz[23] & Kz[18]) ^ (Bz[10] & Kz[24]) ^ (Bz[11] & Kz[15]) ^ (Bz[7] & Kz[23]) ^ (Bz[15] & Kz[7]) ^ (By[19] ^ Ky[16]);
  result[9] = (Bz[1] & Kz[0]) ^ (Bz[0] & Kz[5]) ^ (Bz[19] & Kz[20]) ^ (Bz[11] & Kz[25]) ^ (Bz[13] & Kz[1]) ^ (Bz[16] & Kz[24]) ^ (Bz[24] & Kz[9]) ^ (By[18] ^ Ky[27]);
  result[10] = (Bz[26] & Kz[14]) ^ (Bz[13] & Kz[23]) ^ (Bz[9] & Kz[27]) ^ (Bz[14] & Kz[25]) ^ (Bz[10] & Kz[17]) ^ (Bz[4] & Kz[19]) ^ (Bz[1] & Kz[1]) ^ (By[2] ^ Ky[22]);
  result[11] = (Bz[21] & Kz[6]) ^ (Bz[15] & Kz[21]) ^ (Bz[5] & Kz[17]) ^ (Bz[3] & Kz[15]) ^ (Bz[13] & Kz[26]) ^ (Bz[25] & Kz[11]) ^ (Bz[16] & Kz[16]) ^ (By[27] ^ Ky[7]);
  result[12] = (Bz[20] & Kz[11]) ^ (Bz[7] & Kz[22]) ^ (Bz[18] & Kz[20]) ^ (Bz[12] & Kz[0]) ^ (Bz[17] & Kz[26]) ^ (Bz[1] & Kz[23]) ^ (Bz[16] & Kz[17]) ^ (By[0] ^ Ky[2]);
  result[13] = (Bz[14] & Kz[8]) ^ (Bz[23] & Kz[4]) ^ (Bz[1] & Kz[3]) ^ (Bz[12] & Kz[14]) ^ (Bz[24] & Kz[20]) ^ (Bz[6] & Kz[26]) ^ (Bz[18] & Kz[23]) ^ (By[9] ^ Ky[15]);
  result[14] = (Bz[19] & Kz[19]) ^ (Bz[6] & Kz[0]) ^ (Bz[21] & Kz[18]) ^ (Bz[25] & Kz[2]) ^ (Bz[23] & Kz[13]) ^ (Bz[1] & Kz[8]) ^ (Bz[10] & Kz[24]) ^ (By[8] ^ Ky[14]);
  result[15] = (Bz[3] & Kz[16]) ^ (Bz[0] & Kz[21]) ^ (Bz[27] & Kz[24]) ^ (Bz[23] & Kz[25]) ^ (Bz[19] & Kz[12]) ^ (Bz[8] & Kz[27]) ^ (Bz[4] & Kz[15]) ^ (By[7] ^ Ky[18]);
  result[16] = (Bz[6] & Kz[3]) ^ (Bz[5] & Kz[5]) ^ (Bz[14] & Kz[8]) ^ (Bz[22] & Kz[25]) ^ (Bz[24] & Kz[7]) ^ (Bz[18] & Kz[27]) ^ (Bz[2] & Kz[2]) ^ (By[21] ^ Ky[26]);
  result[17] = (Bz[3] & Kz[11]) ^ (Bz[4] & Kz[14]) ^ (Bz[2] & Kz[23]) ^ (Bz[6] & Kz[17]) ^ (Bz[22] & Kz[22]) ^ (Bz[14] & Kz[13]) ^ (Bz[12] & Kz[19]) ^ (By[26] ^ Ky[4]);
  result[18] = (Bz[25] & Kz[1]) ^ (Bz[21] & Kz[16]) ^ (Bz[19] & Kz[14]) ^ (Bz[9] & Kz[11]) ^ (Bz[10] & Kz[12]) ^ (Bz[15] & Kz[6]) ^ (Bz[13] & Kz[10]) ^ (By[22] ^ Ky[19]);
  result[19] = (Bz[23] & Kz[21]) ^ (Bz[11] & Kz[1]) ^ (Bz[10] & Kz[10]) ^ (Bz[20] & Kz[20]) ^ (Bz[1] & Kz[18]) ^ (Bz[12] & Kz[26]) ^ (Bz[14] & Kz[9]) ^ (By[4] ^ Ky[13]);
  result[20] = (Bz[11] & Kz[20]) ^ (Bz[26] & Kz[21]) ^ (Bz[20] & Kz[9]) ^ (Bz[17] & Kz[25]) ^ (Bz[8] & Kz[12]) ^ (Bz[23] & Kz[3]) ^ (Bz[0] & Kz[15]) ^ (By[24] ^ Ky[0]);
  result[21] = (Bz[9] & Kz[18]) ^ (Bz[17] & Kz[12]) ^ (Bz[26] & Kz[21]) ^ (Bz[4] & Kz[27]) ^ (Bz[27] & Kz[1]) ^ (Bz[0] & Kz[16]) ^ (Bz[15] & Kz[24]) ^ (By[6] ^ Ky[20]);
  result[22] = (Bz[22] & Kz[13]) ^ (Bz[12] & Kz[0]) ^ (Bz[2] & Kz[3]) ^ (Bz[10] & Kz[16]) ^ (Bz[7] & Kz[22]) ^ (Bz[20] & Kz[11]) ^ (Bz[25] & Kz[26]) ^ (By[13] ^ Ky[9]);
  result[23] = (Bz[27] & Kz[2]) ^ (Bz[24] & Kz[0]) ^ (Bz[26] & Kz[13]) ^ (Bz[8] & Kz[5]) ^ (Bz[0] & Kz[4]) ^ (Bz[9] & Kz[8]) ^ (Bz[18] & Kz[10]) ^ (By[23] ^ Ky[3]);
}

void BS_HDCPRound(BS_HDCPCipherState *hs, bsvec_t output[24])
{
  bsvec_t t;

  if (output)
    BS_OutputFunction(hs->bm.B[2], hs->bm.B[1], hs->bm.K[2], hs->bm.K[1], output);
  BS_BlockModule(&hs->bm);
  t = BS_LFSRModule_clock(&hs->lm);
  if (hs->rekey)
    hs->bm.K[1][13] = t;
}

void BS_HDCP_print(int which, BS_LFSRModule *lm,
		   bsvec_t Kz[28], bsvec_t Ky[28], bsvec_t Kx[28],
		   bsvec_t Bz[28], bsvec_t By[28], bsvec_t Bx[28],
		   bsvec_t output[24])
{
  BS_print(28, which, Kx); printf (" ");
  BS_print(28, which, Ky); printf (" ");
  BS_print(28, which, Kz); printf (" ");
  BS_print(28, which, Bx); printf (" ");
  BS_print(28, which, By); printf (" ");
  BS_print(28, which, Bz); printf (" ");
  if (output) {
    BS_print(24, which, output); 
    printf(" ");
  }
  if (lm) {
    printf("  ");
    BS_LFSRModule_print(lm, which);
  }
  printf("\n");
}

void BS_HDCPBlockCipher(bsvec_t K_[56], bsvec_t REPEATER_Bin[65], 
                        BS_HDCPCipherState *hs, bsvec_t Ki[56], 
                        bsvec_t Ri[16], bsvec_t Mi[64])
{
  int i;
  bsvec_t output[24];

  memset(hs->bm.K, 0, sizeof(hs->bm.K));
  memset(hs->bm.B, 0, sizeof(hs->bm.B));
  hs->rekey = 0;

  /*  Load initial keys */
  memcpy(hs->bm.K, K_, 56 * sizeof(bsvec_t));
  memcpy(hs->bm.B, REPEATER_Bin, 65 * sizeof(bsvec_t));

  /*  48 warm-up rounds */
  for (i = 0; i < 48; i++)
    BS_BlockModule(&hs->bm);

  /* Save the output to Ki */
  memcpy(Ki, hs->bm.B, 56 * sizeof(bsvec_t));

  /*  Reload */
  BS_LFSRModule_init(&hs->lm, (bsvec_t *)hs->bm.B);
  memcpy(hs->bm.K, hs->bm.B, sizeof(hs->bm.K));
  memset(hs->bm.B, 0, sizeof(hs->bm.B));
  memcpy(hs->bm.B, REPEATER_Bin, 65 * sizeof(bsvec_t));  
  hs->rekey = 1;

  /*  54 additional rounds */
  for (i = 0; i < 52; i++)
    BS_HDCPRound(hs, NULL);

  /* Four more rounds, with output to Mi and Ri.  Note that we only
     need to compute the output function for the last round. */
  BS_HDCPRound(hs, output);
  memcpy(Mi+48, output, 16 * sizeof(bsvec_t));

  BS_HDCPRound(hs, output);
  memcpy(Mi+32, output, 16 * sizeof(bsvec_t));

  BS_HDCPRound(hs, output);
  memcpy(Mi+16, output, 16 * sizeof(bsvec_t));
  memcpy(Ri+8, output+16, 8 * sizeof(bsvec_t));

  BS_HDCPRound(hs, output);
  //BS_OutputFunction(hs->bm.B[2], hs->bm.B[1], hs->bm.K[2], hs->bm.K[1], output);
  memcpy(Mi, output, 16 * sizeof(bsvec_t));
  memcpy(Ri, output+16, 8 * sizeof(bsvec_t));

  hs->rekey = 0;
}

/* Execute n copies of the HDCP block cipher, with initialization key
   K_, and nonce Bin.  The cipherstate hs will be initialized, and the
   outputs Ki, Ri, and Mi returned.
   - during authentication, pass Km = K_ , and the output Ki = Ks.
   - during vertical blanks, pass Ks = K_.
 */
void HDCPBlockCipher(int ncopies, bsvec_t *K_, bsvec_t *REPEATER, bsvec_t *Bin, 
                     BS_HDCPCipherState *hs, bsvec_t *Ki, bsvec_t *Ri, bsvec_t *Mi)
{
  bsvec_t BSK_[56];
  bsvec_t BSREPEATER_Bin[65];
  bsvec_t BSKi[56];
  bsvec_t BSRi[16];
  bsvec_t BSMi[64];

  BitSlice(ncopies, K_, 56, BSK_);
  BitSlice(ncopies, Bin, 64, BSREPEATER_Bin);
  BitSlice(ncopies, REPEATER, 1, BSREPEATER_Bin + 64);
  BS_HDCPBlockCipher(BSK_, BSREPEATER_Bin, hs, BSKi, BSRi, BSMi);
  BitSlice(56, BSKi, ncopies, Ki);
  BitSlice(16, BSRi, ncopies, Ri);
  BitSlice(64, BSMi, ncopies, Mi);
}

void BS_HDCPStreamCipher(BS_HDCPCipherState *hs, int noutputs, bsvec_t outputs[noutputs][24])
{
  int i;

  hs->rekey = 0;
  for (i = 0; i < noutputs; i++)
    BS_HDCPRound(hs, outputs[i]);
}

void HDCPStreamCipher(int ncopies, BS_HDCPCipherState *hs, int noutputs, uint32_t outputs[noutputs][ncopies])
{
  bsvec_t bs_outputs[noutputs][24];
  int i;

  BS_HDCPStreamCipher(hs, noutputs, bs_outputs);
  for (i = 0; i < noutputs; i++) {
    BitSlice24(24, bs_outputs[i], ncopies, outputs[i]);
  }
}

void HDCPRekeycipher(BS_HDCPCipherState *hs)
{
  int i;
  hs->rekey = 1;
  for (i = 0; i < 56; i++)
    BS_HDCPRound(hs, NULL);
  hs->rekey = 0;
}

void HDCPAuthentication(bsvec_t Km, bsvec_t REPEATER, bsvec_t An, bsvec_t *Ks, bsvec_t *R0, bsvec_t *M0)
{
  BS_HDCPCipherState hs;
  HDCPBlockCipher(1, &Km, &REPEATER, &An, &hs, Ks, R0, M0);
}

/* Given Km, REPEATER, and An, set up the cipher state for the first
   nframe frames, and return other authentication values.  */
void HDCPInitializeMultiFrameState(int nframes, bsvec_t Ks, bsvec_t REPEATER, bsvec_t Mi0, 
                                   BS_HDCPCipherState *hs, 
                                   bsvec_t *Ki, bsvec_t *Ri, bsvec_t *Mi)
{
  int i;
  bsvec_t Ks_[nframes], REPEATER_[nframes], Mi_[nframes+1];

  for (i = 0; i < nframes; i++) {
    Ks_[i] = Ks;
    REPEATER_[i] = REPEATER;
  }
  
  HDCPBlockCipher(1, &Ks, &REPEATER, &Mi0, hs, Ki, Ri, Mi_);

  /* Compute all the Mi values */
  for (i = 0; i < nframes-1; i++) {
    HDCPBlockCipher(nframes, Ks_, REPEATER_, Mi_, hs, Ki, Ri, &Mi_[1]);
  }

  memcpy(Mi, Mi_, nframes * sizeof(*Mi));
}

/* This function assumes that hs holds the initial cipher state for each frame. */
void HDCPFrameStream(int nframes, int height, int width, BS_HDCPCipherState *hs, 
                     uint32_t outputs[height][width][nframes])
{
  int line;

  for (line = 0; line < height; line++) {
    HDCPStreamCipher(nframes, hs, width, outputs[line]);
    HDCPRekeycipher(hs);
  }
}

