//
// Created by serizawa on 18/05/27.
//

#include "ip.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include "param.h"
#include "sock.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

extern PARAM Param;

#define IP_RECV_BUF_NO (16)

typedef struct {
  time_t timestamp;
  int id;
  u_int8_t data[64 * 1024];
  int len;
} IP_RECV_BUF;

IP_RECV_BUF IpRecvBuf[IP_RECV_BUF_NO];

void print_ip(struct ip *ip) {
  static char *proto[] = {"undefined", "ICMP",      "IGMP",      "undefined",
                          "IPIP",      "undefined", "TCP",       "undefined",
                          "EGP",       "undefined", "undefined", "undefined",
                          "PUP",       "undefined", "undefined", "undefined",
                          "undefined", "UDP"};
  char buf1[80];

  printf("ip-------------------------------------------------------------------"
         "-----------\n");

  printf("ip_v=%u,", ip->ip_v);
  printf("ip_hl=%u,", ip->ip_hl);
  printf("ip_tos=%x,", ip->ip_tos);
  printf("ip_len=%d\n", ntohs(ip->ip_len));
  printf("ip_id=%u,", ntohs(ip->ip_id));
  printf("ip_off=%x,%d\n", (ntohs(ip->ip_off)) >> 13 & 0x07,
         ntohs(ip->ip_off) & IP_OFFMASK);
  printf("ip_ttl=%u,", ip->ip_ttl);
  printf("ip_p=%u", ip->ip_p);
  if (ip->ip_p <= 17) {
    printf("(%s),", proto[ip->ip_p]);
  } else {
    printf("(undefined),");
  }
  printf("ip_sum=%04x\n", ntohs(ip->ip_sum));
  printf("ip_src=%s\n", inet_ntop(AF_INET, &ip->ip_src, buf1, sizeof(buf1)));
  printf("ip_dst=%s\n", inet_ntop(AF_INET, &ip->ip_dst, buf1, sizeof(buf1)));

  return;
}

int IpRecvBufInit() {
  for (int i = 0; i < IP_RECV_BUF_NO; i++)
    IpRecvBuf[i].id = -1;

  return (0);
}

/*
 * IpRecvBufAdd
 * IP受信バッファから新しいバッファを確保する関数
 */
int IpRecvBufAdd(u_int16_t id) {
  int freeNo, oldestNo, intoNo;
  time_t oldestTime;

  freeNo = -1;
  oldestTime = ULONG_MAX;
  oldestNo = -1;

  for (int i = 0; i < IP_RECV_BUF_NO; i++) {
    if (IpRecvBuf[i].id == -1)
      freeNo = i;
    else {
      if (IpRecvBuf[i].id == id)
        return (i);
      if (IpRecvBuf[i].timestamp < oldestTime) {
        oldestTime = IpRecvBuf[i].timestamp;
        oldestNo = i;
      }
    }
  }

  if (freeNo == -1)
    intoNo = oldestNo;
  else
    intoNo = freeNo;

  IpRecvBuf[intoNo].timestamp = time(NULL);
  IpRecvBuf[intoNo].id = id;
  IpRecvBuf[intoNo].len = 0;

  return (intoNo);
}

int IpRecvBufDel(u_int16_t id) {
  int bufId = IpRecvBufSearch(id);
  if (bufId < 0)
    return (0);

  IpRecvBuf[bufId].id = -1;
  return (1);
}

int IpRecvBufSearch(u_int16_t id) {
  for (int i = 0; i < IP_RECV_BUF_NO; i++) {
    if (IpRecvBuf[i].id == id) {
      return (i);
    }
  }

  return (-1);
}

/*
 * IpRecv
 * IP受信処理を行なう関数
 * IPヘッダのオプションはここでは利用しないので，読み飛ばす
 * IP_MFビットが立っていたら，まだフラグメントされたデータがあるので解析は行わず
 * 立っていない場合はすべてのデータが揃ったので，ICMPの時はIcmpRecvで処理して
 * IpRecvBufDelで受信バッファを削除しておく
 */
int IpRecv(int soc, u_int8_t *raw, int raw_len, struct ether_header *eh,
           u_int8_t *data, int len) {
  struct ip *ip;
  u_int8_t option[1500];
  u_int16_t sum;
  int optionLen, no, off, plen;
  u_int8_t *ptr = data;

  if (len < (int)sizeof(struct ip)) {
    printf("len(%d)<sizeof(struct ip)\n", len);
    return (-1);
  }

  ip = (struct ip *)ptr;
  ptr += sizeof(struct ip);
  len -= sizeof(struct ip);

  optionLen = ip->ip_hl * 4 - sizeof(struct ip);
  if (optionLen > 0) {
    if (optionLen >= 1500) {
      printf("IP optionLen(%d) too big\n", optionLen);
      return (-1);
    }

    memcpy(option, ptr, optionLen);
    ptr += optionLen;
    len -= optionLen;
  }

  if (optionLen == 0)
    sum = checksum((u_int8_t *)ip, sizeof(struct ip));
  else
    sum = checksum2((u_int8_t *)ip, sizeof(struct ip), option, optionLen);

  if (sum != 0 && sum != 0xFFFF) {
    printf("bad ip checksum\n");
    return (-1);
  }

  plen = ntohs(ip->ip_len) - ip->ip_hl * 4;

  no = IpRecvBufAdd(ntohs(ip->ip_id));
  off = (ntohs(ip->ip_off) & IP_OFFMASK) * 8;
  memcpy(IpRecvBuf[no].data + off, ptr, plen);

  // NOTE: IP_MFビットが立ってない場合は解析を進める
  if (!(ntohs(ip->ip_off) & IP_MF)) {
    IpRecvBuf[no].len = off + plen;
    if (ip->ip_p == IPPROTO_ICMP) {
      IcmpRecv(soc, raw, raw_len, eh, ip, IpRecvBuf[no].data,
               IpRecvBuf[no].len);
    }
    IpRecvBufDel(ntohs(ip->ip_id));
  }

  return (0);
}

/*
 * IpSendLink
 * IPデータを送信する関数
 * 実際にはIpSend()が送信している
 * フラグメント禁止の場合はMTUより大きいデータは送れないため
 * エラーを返す
 * MTU以上のサイズの場合にはフラグメントして送信する
 */
int IpSendLink(int soc, u_int8_t smac[6], u_int8_t dmac[6],
               struct in_addr *saddr, struct in_addr *daddr, u_int8_t proto,
               int dontFlagment, int ttl, u_int8_t *data, int len) {
  struct ip *ip;
  u_int8_t *dptr, *ptr, sbuf[ETHERMTU];
  u_int16_t id;

  int rest, sndLen, off, flagment;

  if (dontFlagment && len > Param.MTU - sizeof(struct ip)) {
    printf("IpSend:data too long: %d\n", len);
    return (-1);
  }

  id = random();

  dptr = data;
  rest = len;

  while (rest > 0) {
    if (rest > Param.MTU - sizeof(struct ip)) {
      sndLen = (Param.MTU - sizeof(struct ip)) / 8 * 8;
      flagment = 1;
    } else {
      sndLen = rest;
      flagment = 0;
    }

    ptr = sbuf;
    ip = (struct ip *)ptr;
    memset(ip, 0, sizeof(struct ip));
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_len = htons(sizeof(struct ip) + sndLen);
    ip->ip_id = htons(id);
    off = (dptr - data) / 8;

    if (dontFlagment) {
      ip->ip_off = htons(IP_DF);
    } else if (flagment) {
      ip->ip_off = htons((IP_MF) | (off & IP_OFFMASK));
    } else {
      ip->ip_off = htons((0) | (off & IP_OFFMASK));
    }

    ip->ip_ttl = ttl;
    ip->ip_p = proto;
    ip->ip_src.s_addr = saddr->s_addr;
    ip->ip_dst.s_addr = daddr->s_addr;
    ip->ip_sum = 0;
    ip->ip_sum = checksum((u_int8_t *)ip, sizeof(struct ip));
    ptr += sizeof(struct ip);

    memcpy(ptr, dptr, sndLen);
    ptr += sndLen;

    EtherSend(soc, smac, dmac, ETHERTYPE_IP, sbuf, ptr - sbuf);
    print_ip(ip);

    dptr += sndLen;
    rest -= sndLen;
  }

  return (0);
}

int IpSend(int soc, struct in_addr *saddr, struct in_addr *daddr,
           u_int8_t proto, int dontFlagment, int ttl, u_int8_t *data, int len) {
  u_int8_t dmac[6];
  char buf1[80];
  int ret;

  if (GetTargetMac(soc, daddr, dmac, 0)) {
    ret = IpSendLink(soc, Param.vmac, dmac, saddr, daddr, proto, dontFlagment,
                     ttl, data, len);
  } else {
    printf("IpSend:%s Destination Host Unreachable\n",
           inet_ntop(AF_INET, daddr, buf1, sizeof(buf1)));
    ret -= 1;
  }

  return (ret);
}
