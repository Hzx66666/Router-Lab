//#define ROUTER_BACKEND_LINUX
#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer, bool split, in_addr_t dst_addr);
extern std::vector<RoutingTableEntry> getRouterTable();

RipPacket ripTable;
macaddr_t multicast_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x16}; // 01:00:5e:00:00:09
in_addr_t multicast_addr = 0x090000e0;                          // 224.0.0.9
uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
//每个网口上绑定的 IP 地址
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
unsigned short getCheckSum(uint8_t output[2048], int hLength)
{
  int sum = 0;
  for (int i = 0; i < hLength; i++)
  {
    if (i % 2 == 0)
    {
      sum += ((int)output[i]) << 8;
    }
    else
    {
      sum += ((int)output[i]);
    }
  }
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  unsigned short answer = ~sum;
  return answer;
}
uint32_t sendIPPacket(uint8_t output[2048], in_addr_t src_addr, in_addr_t dst_addr, bool split)
{
  // IP
  output[0] = 0x45;
  output[1] = 0x00;
  //ID
  output[4] = 0x00;
  output[5] = 0x00;
  //Falg
  output[6] = 0x00;
  output[7] = 0x00;
  //TTL
  output[8] = 0x01;
  //Protocol
  output[9] = 0x11;

  output[20] = 0x02;
  output[21] = 0x08;

  // port = 520 (dest)
  output[22] = 0x02;
  output[23] = 0x08;
  // Source
  output[12] = src_addr;
  output[13] = src_addr >> 8;
  output[14] = src_addr >> 16;
  output[15] = src_addr >> 24;

  // Destination
  output[16] = dst_addr;
  output[17] = dst_addr >> 8;
  output[18] = dst_addr >> 16;
  output[19] = dst_addr >> 24;

  uint32_t rip_len = assemble(&ripTable, &output[20 + 8], split, dst_addr);

  // Total Length
  output[2] = (rip_len + 20 + 8) >> 8;
  output[3] = rip_len + 20 + 8;

  // UDP len
  output[24] = (rip_len + 8) >> 8;
  output[25] = rip_len + 8;

  // ip checksum
  output[10] = 0x00;
  output[11] = 0x00;
  unsigned short answer = getCheckSum(output, 20);
  output[10] = answer >> 8;
  output[11] = answer;

  // udp checksum
  output[26] = 0x00;
  output[27] = 0x00;
  return rip_len;
}
void setupICMPPacket(uint8_t *output, uint8_t *packet)
{
  // ICMP checksum
  output[2] = 0x00;
  output[3] = 0x00;

  // no use
  output[4] = 0x00;
  output[5] = 0x00;
  output[6] = 0x00;
  output[7] = 0x00;

  // IP head + 64 bits of data
  for (int i = 0; i < 28; i++)
  {
    output[i + 8] = packet[i];
  }
}
uint32_t changeEndian_uint32t(uint32_t value)
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
uint32_t toEndian(uint32_t num)
{
  uint32_t tmp = 0;
  for (uint32_t i = 0; i < num; i++)
  {
    tmp = tmp << 1 + 1;
  }
  return tmp << (32 - num);
}
uint32_t toInt(uint32_t num)
{
  uint32_t tmp = 0x00000001;
  uint32_t ret = 32;
  for (uint32_t i = 0; i < 32; i++)
  {
    if (num & tmp == 0)
    {
      ret--;
    }
    else
    {
      break;
    }
    num >> 1;
  }
  return ret;
}

void updateRIPtable()
{
  std::vector<RoutingTableEntry> routertable = getRouterTable();
  ripTable.command = 2;
  ripTable.numEntries = routertable.size();
  for (int i = 0; i < ripTable.numEntries; i++)
  {
    RipEntry entry;
    entry.addr = routertable[i].addr;
    entry.nexthop = routertable[i].nexthop;
    entry.mask = changeEndian_uint32t(toEndian(routertable[i].len));
    printf("! %d\n", routertable[i].len);
    printf("! %d\n", toEndian(routertable[i].len));
    printf("! %d\n", entry.mask);
    entry.metric = changeEndian_uint32t(routertable[i].metric);
    ripTable.entries[i] = entry;
  }
}
int main(int argc, char *argv[])
{
  int res = HAL_Init(1, addrs);
  if (res < 0)
  {
    return res;
  }

  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  //添加至路由表

  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    RoutingTableEntry entry = {
        .addr = addrs[i], // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,     // big endian, means direct
        .metric = 1};
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1)
  {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000)
    {
      // What to do?
      for (int i = 0; i < N_IFACE_ON_BOARD; i++)
      {
        updateRIPtable();
        uint32_t rip_len = sendIPPacket(output, addrs[i], multicast_addr, false);
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, multicast_mac);
      }
      printf("Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                              dst_mac, 1000, &if_index);
    printf("hhhh %d\n", res);
    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    uint8_t version = packet[0] >> 4;
    if (version != 4 && version != 6)
    {
      printf("Invalid version\n");
      continue;
    }

    uint8_t TTL = packet[8];
    if (TTL <= 0)
    {
      printf("Invalid TTL\n");
      continue;
    }

    if (!validateIPChecksum(packet, res))
    {
      printf("Invalid IP Checksum\n");
      continue;
    }
    //***额外的检查
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    memcpy(&dst_addr, &packet[16], sizeof(in_addr_t));
    memcpy(&src_addr, &packet[12], sizeof(in_addr_t));
    src_addr = changeEndian_uint32t(src_addr);
    dst_addr = changeEndian_uint32t(dst_addr);
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }

    // TODO: Handle rip multicast address?
    if (memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0)
    {
      dst_is_me = true;
    }
    if (dst_is_me)
    {
      // TODO: RIP?

      RipPacket rip;
      if (disassemble(packet, res, &rip))
      { //3a.1
        if (rip.command == 1)
        { //3a.3
          // request
          RipPacket resp;

          updateRIPtable();

          // TODO: fill resp
          // assemble
          uint32_t rip_len = sendIPPacket(output, src_addr, dst_addr, true);
          // ...
          // RIP
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        }
        else
        { //3a.2
          // response
          // TODO: use query and update
          /*
          RipPacket invalid_rip;
          invalid_rip.command = 2;
          invalid_rip.numEntries = 0;
          RipPacket update_rip;
          update_rip.command = 2;
          update_rip.numEntries = 0;*/

          for (uint32_t i = 0; i < rip.numEntries; i++)
          {
            RipEntry entry = rip.entries[i];
            if (entry.metric + 1 > 16)
            {
              //删除路由
              RoutingTableEntry router;
              router.addr = entry.addr;
              router.len = toInt(changeEndian_uint32t(entry.metric));
              update(false, router);
              entry.metric++;
              //invalid_rip.entries[invalid_rip.numEntries] = entry;
              //invalid_rip.numEntries++;
            }
            else
            {
              updateRIPtable();
              bool find = false;
              for (int i = 0; i < ripTable.numEntries; i++)
              {
                if (entry.addr == ripTable.entries[i].addr && entry.mask == ripTable.entries[i].mask)
                {
                  if ((entry.metric + 1) <= ripTable.entries[i].metric)
                  {
                    entry.metric++;
                    find = true;
                    RoutingTableEntry router;
                    router.addr = entry.addr;
                    router.len = toInt(changeEndian_uint32t(entry.metric));
                    router.if_index = if_index;
                    router.nexthop = src_addr;
                    router.metric = entry.metric;
                    update(true, router);
                    //添加更新rip报文
                    //update_rip.entries[update_rip.numEntries] = entry;
                    //update_rip.numEntries++;
                  }
                }
              }
              if (!find)
              {
                entry.metric++;
                RoutingTableEntry router;
                router.addr = entry.addr;
                router.len = toInt(changeEndian_uint32t(entry.metric));
                router.if_index = if_index;
                router.nexthop = src_addr;
                router.metric = entry.metric;
                update(true, router);
                //添加更新rip报文
                //update_rip.entries[update_rip.numEntries] = entry;
                //update_rip.numEntries++;
              }
            }
          }
        }
      }
      else
      {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (query(src_addr, &nexthop, &dest_if))
        {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0)
          {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
          {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            if (output[8] == 0x00)
            {
              // ICMP type
              output[0] = 0x0b;
              // ICMP code
              output[1] = 0x00;

              setupICMPPacket(output, packet);

              // calculate checksum
              unsigned short answer = getCheckSum(output, 36);
              output[2] = answer >> 8;
              output[3] = answer;
              HAL_SendIPPacket(if_index, output, 36, src_mac); // 36 is the length of a ICMP packet: 8(head of icmp) + 28(ip head + first 8 bytes of ip data)
              printf("IP TTL timeout for %x\n", src_addr);
            }
            else
            {
              HAL_SendIPPacket(dest_if, output, res, dest_mac);
            }
          }
          else
          {
            // not found
          }
        }
        else
        {
          // not found
          output[0] = 0x03;
          // ICMP code
          output[1] = 0x00;

          setupICMPPacket(output, packet);

          // calculate checksum
          output[2] = 0x00;
          output[3] = 0x00;
          unsigned short answer = getCheckSum(output, 36);
          output[2] = answer >> 8;
          output[3] = answer;
          HAL_SendIPPacket(if_index, output, 36, src_mac); // 36 is the length of a ICMP packet: 8(head of icmp) + 28(ip head + first 8 bytes of ip data)
          printf("IP not found for %x\n", src_addr);
        }
      }
    }
  }
  return 0;
}