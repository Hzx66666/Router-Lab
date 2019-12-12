#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 sum2 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
    int headlen=(int)(packet[0]&0xf)*4;
    uint16_t* buf = (uint16_t*) packet;
    uint32_t sum = 0;
    for (int32_t len = 0; len<headlen; len += 2)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    short answer=~sum;
    if(answer!=0x0000)
        return false;
    
    packet[8]--;
    int sum2 = 0;
    int i=0;
    for(i = 0;i < headlen;i++) {
        if(i != 10 && i != 11){
            if(i % 2 == 0) {
                sum2 += ((int)packet[i]) << 8;
            } else {
                sum2 += (int)packet[i];
            }
        }
    }
    sum2 = (sum2 >> 16) + (sum2 & 0xffff);
    sum2 += (sum2 >> 16);
    sum2 = ~sum2;
    packet[10] = sum2 >> 8;
    packet[11] = sum2;
    return true;
}