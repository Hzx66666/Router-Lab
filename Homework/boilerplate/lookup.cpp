#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
using namespace std;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
vector<RoutingTableEntry> RouterTable;
std::vector<RoutingTableEntry> getRouterTable()
{
  return RouterTable;
}
void update(bool insert, RoutingTableEntry entry)
{
  // TODO:
  if (insert)
  {
    int flag = false;
    for (int i = 0; i < RouterTable.size(); i++)
    {
      if (RouterTable.at(i).addr == entry.addr && RouterTable.at(i).len == entry.len)
      {
        RouterTable.at(i).nexthop = entry.nexthop;
        RouterTable.at(i).if_index = entry.if_index;
        flag = true;
        break;
      }
    }
    if (!flag)
    {
      RouterTable.push_back(entry);
    }
  }
  else
  {
    for (int i = 0; i < RouterTable.size(); i++)
    {
      if (RouterTable.at(i).addr == entry.addr && RouterTable.at(i).len == entry.len)
      {
        RouterTable.erase(RouterTable.begin() + i);
        break;
      }
    }
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
string tohex(uint32_t addr)
{
  int temp = (int)addr;
  stringstream ss;
  ss << hex << temp;
  return ss.str();
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index)
{
  // TODO:
  string addr_hex = tohex(addr);
  int max_prefix = -1;
  int max = -1;
  for (int i = 0; i < RouterTable.size(); i++)
  {
    string entry_addr_hex = tohex(RouterTable.at(i).addr);
    if (addr_hex.find(entry_addr_hex) != -1 && (int)entry_addr_hex.size() > max_prefix)
    {
      max_prefix = entry_addr_hex.length();
      max = i;
    }
  }
  if (max == -1)
    return false;
  else
  {
    *nexthop = RouterTable.at(max).nexthop;
    *if_index = RouterTable.at(max).if_index;
    return true;
  }
}
