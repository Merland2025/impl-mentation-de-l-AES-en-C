#ifndef CHIFF_H
#define CHIFF_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint8_t S_BOX[256];
extern uint8_t IS_BOX[256];
extern int TAB_EXP[256] ;
extern uint8_t TAB_HEX[255];
extern uint8_t RCON[51];

void cipher( uint8_t *in, uint8_t *out,uint8_t **w, int Nb,int Nr);
void Invcipher( uint8_t *in, uint8_t *out,uint8_t **w, int Nb,int Nr);
void KeyExpansion(uint8_t *key, uint8_t **w,int Nk,int Nb,int Nr);
#endif




