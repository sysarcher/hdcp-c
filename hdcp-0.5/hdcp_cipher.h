/************************************************************
 * A bit-sliced implementation of the HDCP authentication protocol.
 *
 * This software is released under the FreeBSD license.
 * Copyright Rob Johnson and Mikhail Rubnich.
 ************************************************************/

#ifndef __HDCP_CIPHER_H__
#define __HDCP_CIPHER_H__

#include <stdint.h>
#include "bitslice.h"

/***********************************************
 * Low-level interface to cipher operations
 ***********************************************/

/* A bit-sliced LFSR with taps and feedbacks.  In order to avoid
   having to actually move around all the state values to perform
   a shift, we just keep track of where the 0 element is and 
   adjust zero to perform shifts. */
typedef struct _BS_LFSReg {
  int taps[3];
  int feedbacks[6];
  int zero;
  int len;
  bsvec_t state[17];
} BS_LFSReg;

typedef struct _BS_LFSRModule
{
  BS_LFSReg lfsrs[4];
  bsvec_t snA[4], snB[4];
} BS_LFSRModule;

typedef struct _BS_HDCPBlockModule
{
  bsvec_t K[3][28], B[3][28];
} BS_HDCPBlockModule;

typedef struct _BS_HDCPCipherState
{
  BS_LFSRModule lm;
  BS_HDCPBlockModule bm;
  int rekey;
} BS_HDCPCipherState;

void BS_HDCPBlockCipher(bsvec_t K_[56], bsvec_t REPEATER_An[65], 
                        BS_HDCPCipherState *hs, bsvec_t Ki[56], bsvec_t Ri[16], bsvec_t Mi[64]);

void HDCPBlockCipher(int ncopies, bsvec_t *K_, bsvec_t *REPEATER, bsvec_t *An, 
                     BS_HDCPCipherState *hs, bsvec_t *Ki, bsvec_t *Ri, bsvec_t *Mi);

void BS_HDCPStreamCipher(BS_HDCPCipherState *hs, int noutputs, bsvec_t outputs[noutputs][24]);

void HDCPStreamCipher(int ncopies, BS_HDCPCipherState *hs, int noutputs, uint32_t outputs[noutputs][ncopies]);

void HDCPRekeycipher(BS_HDCPCipherState *hs);

/*************************************************
 * High-level interface for implementing the HDCP protocol 
 *************************************************/

/* Generate Ks, R0, and M0 from Km, REPEATER, and An */
void HDCPAuthentication(bsvec_t Km, bsvec_t REPEATER, bsvec_t An, 
                        bsvec_t *Ks, bsvec_t *R0, bsvec_t *M0);

/* Generate the following information for the next nframe frames:
   - initialize hs for generating ciphertext
   - output Ki, Ri, and Mi for each frame */
void HDCPInitializeMultiFrameState(int nframes, bsvec_t Ks, bsvec_t REPEATER, bsvec_t Mi0, 
                                   BS_HDCPCipherState *hs, bsvec_t *Ki, bsvec_t *Ri, bsvec_t *Mi);

/* Given hs as initialized by HDCPInitializeMultiFrameState, generate
   ciphertext output for the next nframe frames.  hs will also be
   updated, so you can call this function several times if you want to
   generate the output in chunks. */
void HDCPFrameStream(int nframes, int height, int width, BS_HDCPCipherState *hs, 
                     uint32_t outputs[height][width][nframes]);

#endif /* __HDCP_CIPHER_H__ */

