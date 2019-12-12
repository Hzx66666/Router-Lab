#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
using namespace std;

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
    
    int headlen=(int)(packet[0]&0xf)*4;
    
    uint16_t* buf = (uint16_t*) packet;
    uint32_t sum = 0;
    for (int32_t len = 0; len<headlen; len += 2)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    short answer=~sum;
    if(answer==0x0000)
  return true;
    else return false;
}
