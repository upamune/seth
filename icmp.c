//
// Created by serizawa on 18/05/27.
//

#include "icmp.h"
#include "ether.h"
#include "ip.h"
#include "param.h"
#include "sock.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

extern PARAM Param;

#define ECHO_HDR_SIZE (8)

#define PING_SEND_NO (4)

typedef struct {
  struct timeval sendTime;
} PING_DATA;

PING_DATA PingData[PING_SEND_NO];

int print_icmp(struct icmp *icmp) {
  static char *icmp_type[] = {"Echo Reply",
                              "undefined",
                              "undefined",
                              "Destination Unreachable",
                              "Source Quench",
                              "Redirect",
                              "undefined",
                              "undefined",
                              "Echo Request",
                              "Router Adverisement",
                              "Router Selection",
                              "Time Exceeded for Datagram",
                              "Parameter Problem on Datagram",
                              "Timestamp Request",
                              "Timestamp Reply",
                              "Information Request",
                              "Information Reply",
                              "Address Mask Request",
                              "Address Mask Reply"};

  printf("icmp------------------------------------\n");

  printf("icmp_type=%u", icmp->icmp_type);
  if (icmp->icmp_type <= 18) {
    printf("(%s),", icmp_type[icmp->icmp_type]);
  } else {
    printf("(undefined),");
  }
  printf("icmp_code=%u,", icmp->icmp_code);
  printf("icmp_cksum=%u\n", ntohs(icmp->icmp_cksum));

  if (icmp->icmp_type == 0 || icmp->icmp_type == 8) {
    printf("icmp_id=%u,", ntohs(icmp->icmp_id));
    printf("icmp_seq=%u\n", ntohs(icmp->icmp_seq));
  }

  printf("icmp------------------------------------\n");

  return (0);
}

/*
 * IcmpSendEchoReply
 * ICMPエコー応答を送信する関数
 * icmp_typeに ICMP_ECHOREPLYを指定して，
 * チェックサム計算したり色んなデータをえいやっとやって
 * 最終的にIpSend() で送信する
 */
int IcmpSendEchoReply(int soc, struct ip *r_ip, struct icmp *r_icmp,
                      u_int8_t *data, int len, int ip_ttl) {
  u_int8_t *ptr;
  u_int8_t sbuf[64 * 1024];
  struct icmp *icmp;

  ptr = sbuf;

  icmp = (struct icmp *)ptr;
  memset(icmp, 0, sizeof(struct icmp));
  icmp->icmp_type = ICMP_ECHOREPLY;
  icmp->icmp_code = 0;
  icmp->icmp_hun.ih_idseq.icd_id = r_icmp->icmp_hun.ih_idseq.icd_id;
  icmp->icmp_hun.ih_idseq.icd_seq = r_icmp->icmp_hun.ih_idseq.icd_seq;
  icmp->icmp_cksum = 0;

  ptr += ECHO_HDR_SIZE;

  memcpy(ptr, data, len);
  ptr += len;

  icmp->icmp_cksum = checksum(sbuf, ptr - sbuf);

  printf("=== ICMP reply ===[\n");
  IpSend(soc, &r_ip->ip_dst, &r_ip->ip_src, IPPROTO_ICMP, 0, ip_ttl, sbuf,
         ptr - sbuf);
  print_icmp(icmp);
  printf("]\n");

  return (0);
}

int IcmpSendEcho(int soc, struct in_addr *daddr, int seqNo, int size) {
  int psize;
  u_int8_t *ptr;
  u_int8_t sbuf[64 * 1024];
  struct icmp *icmp;

  ptr = sbuf;
  icmp = (struct icmp *)ptr;
  memset(icmp, 0, sizeof(struct icmp));
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_hun.ih_idseq.icd_id = htons((u_int16_t)getpid());
  icmp->icmp_hun.ih_idseq.icd_seq = htons((u_int16_t)seqNo);
  icmp->icmp_cksum = 0;

  ptr += ECHO_HDR_SIZE;

  psize = size - ECHO_HDR_SIZE;
  for (int i = 0; i < psize; i++) {
    *ptr = (i & 0xFF);
    ptr++;
  }

  icmp->icmp_cksum = checksum((u_int8_t *)sbuf, ptr - sbuf);

  printf("=== ICMP echo ===[\n");

  IpSend(soc, &Param.vip, daddr, IPPROTO_ICMP, 0, Param.IpTTL, sbuf,
         ptr - sbuf);
  print_icmp(icmp);
  printf("]\n");

  gettimeofday(&PingData[seqNo - 1].sendTime, NULL);

  return (0);
}

int PingSend(int soc, struct in_addr *daddr, int size) {
  for (int i = 0; i < PING_SEND_NO; i++) {
    IcmpSendEcho(soc, daddr, i + 1, size);
    sleep(1);
  }

  return (0);
}

/*
 * IcmpRecv
 * 受信したIPパケットがICMPの場合に処理するための関数
 * 自分宛の宛先IPアドレスであれば，標準出力に表示する
 * icmp_type がICMP_ECHOなら，ICMPエコー応答を返答し，
 * ICMP_ECHO_REPLYならICMPエコー応答をチェックする
 */
int IcmpRecv(int soc, u_int8_t *raw, int raw_len, struct ether_header *eh,
             struct ip *ip, u_int8_t *data, int len) {
  struct icmp *icmp;
  u_int16_t sum;
  int icmpSize;
  u_int8_t *ptr = data;

  icmpSize = len;

  icmp = (struct icmp *)ptr;
  ptr += ECHO_HDR_SIZE;
  len -= ECHO_HDR_SIZE;

  sum = checksum((u_int8_t *)icmp, icmpSize);
  if (sum != 0 && sum != 0xFFFF) {
    printf("bad icmp checksum(%x, %x)\n", sum, icmp->icmp_cksum);
    return (-1);
  }

  if (isTargetIPAddr(&ip->ip_dst)) {
    printf("--- recv ---[\n");
    print_ether_header(eh);
    print_ip(ip);
    print_icmp(icmp);
    printf("]\n");

    if (icmp->icmp_type == ICMP_ECHO)
      IcmpSendEchoReply(soc, ip, icmp, ptr, len, Param.IpTTL);
    else if (icmp->icmp_type == ICMP_ECHOREPLY)
      PingCheckReply(ip, icmp);
  }

  return (0);
}

/*
 * PingCheckReply
 * ICMPエコー応答を受信した場合にチェックする関数
 * IDがプロセスIDと一致しているかどうか確認して，
 * シーケンス番号に応じて送信時刻との時間差を計算して
 * 結果を表示する
 */
int PingCheckReply(struct ip *ip, struct icmp *icmp) {
  char buf1[80];

  if (ntohs(icmp->icmp_id) == getpid()) {
    int seqNo = ntohs(icmp->icmp_seq);
    if (seqNo > 0 && seqNo <= PING_SEND_NO) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      int sec = tv.tv_sec - PingData[seqNo - 1].sendTime.tv_sec;
      int usec = tv.tv_usec - PingData[seqNo - 1].sendTime.tv_usec;

      if (usec < 0) {
        sec--;
        usec = 100000 - usec;
      }

      printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%d.%03d ms\n",
             ntohs(ip->ip_len),
             inet_ntop(AF_INET, &ip->ip_src, buf1, sizeof(buf1)),
             ntohs(icmp->icmp_seq), ip->ip_ttl, sec, usec);
    }
  }

  return (0);
}
