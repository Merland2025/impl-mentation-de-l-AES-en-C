#ifndef AES_H
#define AES_H

#define VERSION 1
#define SUBVERSION 0
#define REVISION 0

#define DEFAULT_KEY_SIZE 4
#define DEFAULT_BLOCK_SIZE 4
#define DEFAULT_NUMBER_ROUND 10
#define DEFAULT_MODE 1

extern unsigned char *file_content(const char *filename, size_t *size);
extern uint8_t *hex_content(const unsigned char *input, size_t size);

#include <stdint.h>

extern uint8_t DEFAULT_KEY[16];
extern uint8_t DEFAULT_IV[16];

#endif /* AES_H */

