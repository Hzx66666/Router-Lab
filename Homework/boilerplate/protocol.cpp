#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <iostream>
using namespace std;

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
  // TODO:
  //Total length
  if ((((int)packet[2]) << 8) + packet[3] > len)
    return false;
  //command
  uint8_t command = packet[28];
  if (command != 0x01 && command != 0x02)
    return false;
  //version
  if (packet[29] != 0x02)
    return false;
  //zero
  if ((((uint16_t)packet[30]) << 8) + packet[31] != 0x0000)
    return false;
  output->numEntries = 0;
  output->command = command;
  int entry_start = ((packet[0] & 0xf) << 2) + 12;
  for (int i = entry_start; i < len; i += 20)
  {
    //family
    uint16_t family = ((int)packet[i] << 8) + packet[1 + i];
    if (command == 0x01)
    {
      if (family != 0x0000)
        return false;
    }
    else
    {
      if (family != 0x0002)
        return false;
    }
    //Metric
    uint32_t metric = ((int)packet[16 + i] << 24) + ((int)packet[17 + i] << 16) + ((int)packet[18 + i] << 8) + packet[19 + i];
    if (metric < 1 || metric > 16)
      return false;
    //Mask
    uint32_t mask = ((int)packet[8 + i] << 24) + ((int)packet[9 + i] << 16) + ((int)packet[10 + i] << 8) + packet[11 + i];
    int cnt = 0;
    uint8_t current;
    uint8_t forward;
    uint8_t first = mask & 0x1;
    forward = mask & 0x1;
    for (int i = 1; i < 32; i++)
    {
      mask = mask >> 1;
      current = mask & 0x1;
      if (current != forward)
      {
        cnt++;
      }
      forward = current;
    }
    if (cnt > 1)
      return false;
    if (first == 0x1 && cnt > 0)
      return false;

    //赋值
    output->entries[output->numEntries].addr = ((int)packet[7 + i] << 24) + ((int)packet[6 + i] << 16) + ((int)packet[5 + i] << 8) + packet[4 + i];
    output->entries[output->numEntries].mask = ((int)packet[11 + i] << 24) + ((int)packet[10 + i] << 16) + ((int)packet[9 + i] << 8) + packet[8 + i];
    output->entries[output->numEntries].metric = ((int)packet[19 + i] << 24) + ((int)packet[18 + i] << 16) + ((int)packet[17 + i] << 8) + packet[16 + i];
    output->entries[output->numEntries].nexthop = ((int)packet[15 + i] << 24) + ((int)packet[14 + i] << 16) + ((int)packet[13 + i] << 8) + packet[12 + i];
    output->numEntries++;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t changeEndian_uint32t2(uint32_t value)
{
  char *ptr = (char *)(&value);
  uint64_t base[4]; // 设置基
  base[0] = 1;
  for (int i = 1; i < 4; ++i)
  {
    base[i] = base[i - 1] * 256;
  }

  uint32_t res = 0;
  for (int i = 0; i < sizeof(value); ++i)
  {
    res += uint8_t(ptr[i]) * base[4 - i - 1];
  }

  return res;
}
uint32_t assemble(const RipPacket *rip, uint8_t *buffer, uint32_t if_index)
{
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 0x02;
  buffer[2] = 0x00;
  buffer[3] = 0x00;
  int j = 4;
  for (int i = 0; i < rip->numEntries; i++)
  {
    //水平分割
    RipEntry entry = rip->entries[i];

    //family
    buffer[j] = 0x00;
    if (rip->command == 0x02)
      buffer[j + 1] = 0x02;
    else
      buffer[j + 1] = 0x00;
    //Router Tag
    buffer[j + 2] = 0x00;
    buffer[j + 3] = 0x00;
    //ip address
    buffer[j + 4] = entry.addr;
    buffer[j + 5] = entry.addr >> 8;
    buffer[j + 6] = entry.addr >> 16;
    buffer[j + 7] = entry.addr >> 24;
    //mask

    buffer[j + 8] = entry.mask;
    buffer[j + 9] = entry.mask >> 8;
    buffer[j + 10] = entry.mask >> 16;
    buffer[j + 11] = entry.mask >> 24;
    //nexthop
    buffer[j + 12] = entry.nexthop;
    buffer[j + 13] = entry.nexthop >> 8;
    buffer[j + 14] = entry.nexthop >> 16;
    buffer[j + 15] = entry.nexthop >> 24;
    //metric
    if (if_index == entry.if_index)
    {
      entry.metric = changeEndian_uint32t2(16);
    }
    buffer[j + 16] = entry.metric;
    buffer[j + 17] = entry.metric >> 8;
    buffer[j + 18] = entry.metric >> 16;
    buffer[j + 19] = entry.metric >> 24;
    j += 20;
  }

  return (rip->numEntries) * 20 + 4;
  ;
}
