#ifndef CRC_H_
#define CRC_H_

#include <stdint.h>

uint16_t Crc16(unsigned char *pcBlock, unsigned short len);
unsigned char Crc8(unsigned char *pcBlock, unsigned int len);

#endif // CRC_H_
