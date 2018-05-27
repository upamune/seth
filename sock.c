//
// Created by serizawa on 18/05/27.
//

#include "sock.h"
#include "param.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <linux/if.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

/*
 * checksum
 * 16ビットごとの1の補数和を取り, さらにそれの1の補数を取る
 * IP, ICMP, UDP, TCP全てチェックサムの計算方法は同じ
 * ただし、UDPに関しては計算結果が0x0000の場合に0xFFFFにする
 */
u_int16_t checksum(u_int8_t *data, int len) {
  u_int32_t sum;
  u_int16_t *ptr;
  int c;

  sum = 0;
  ptr = (u_int16_t *)data;
  for (c = len; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }

  if (c == 1) {
    u_int16_t val;
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (~sum);
}

/*
 * checksum2
 * checksum() のデータを2つ渡せるバージョン
 */
u_int16_t checksum2(u_int8_t *data1, int len1, u_int8_t *data2, int len2) {
  u_int32_t sum;
  u_int16_t *ptr;
  int c;

  sum = 0;
  ptr = (u_int16_t *)data1;
  for (c = len1; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    u_int16_t val;
    val = ((*ptr) << 8) + (*data2);
    sum += val;
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr = (u_int16_t *)(data2 + 1);
    len2--;
  } else {
    ptr = (u_int16_t *)data2;
  }
  for (c = len2; c > 1; c -= 2) {
    sum += (*ptr);
    if (sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    ptr++;
  }
  if (c == 1) {
    u_int16_t val;
    val = 0;
    memcpy(&val, ptr, sizeof(u_int8_t));
    sum += val;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (~sum);
}

/*
 * GetMacAddress
 * 指定したインターフェースのMACアドレスを取得する関数
 * ioctl() にSIOCGIFHWADDR を指定すると得ることができる
 */
int GetMacAddress(char *device, u_int8_t *hwaddr) {
  struct ifreq ifreq;
  int soc;
  u_int8_t *p;

  if ((soc = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("GetMacAddress():socket");
    return (-1);
  }

  // NOTE:
  // srcの長さがnよりも短い場合,strncpy()はdestに追加のヌルバイトを書き込み,
  // 全部でnバイトが書き込まれるようになる
  strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

  if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1) {
    perror("GetMacAddress():ioctl:hwaddr");
    close(soc);
    return (-1);
  }

  p = (u_int8_t *)*ifreq.ifr_hwaddr.sa_data;

  // NOTE: 6とは? :thinking_face:
  memcpy(hwaddr, p, 6);
  close(soc);

  return (1);
}

/*
 * DummyWait
 * 指定したミリ秒スリープする関数
 */
int DummyWiat(int ms) {
  struct timespec ts;

  ts.tv_sec = 0;
  ts.tv_nsec = ms * 1000 * 1000;

  nanosleep(&ts, NULL);

  return 0;
}

/*
 * init_socket
 * リンクレイヤーソケットを準備してディスクリプタを返す
 * 自分宛以外のパケットも受信対象にしている
 */
int init_socket(char *device) {
  struct ifreq if_req;
  struct socketaddr_ll sa;
  int soc;

  // NOTE: htons()関数はunsigned short integer hostshort を
  // ホストバイトオーダーからネットワークバイトオーダーに変換.
  if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return (-1);
  }

  strcpy(if_req.ifr_name, device);

  // NOTE: インターフェース番号を取得する
  if (ioctl(soc, SIOCGIFINDEX, &if_req) < 0) {
    perror("ioctl");
    close(soc);
    return (-1);
  }

  sa.sll_family = PF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = if_req.ifr_ifindex;

  // NOTE: bindすると,
  // 指定したネットワークインターフェースから送受信できるようになる bind()
  // は、ファイルディスクリプター sockfd で参照されるソケットに addr
  // で指定されたアドレスを割り当てる. addrlen には addr
  // が指すアドレス構造体のサイズをバイト単位で指定する.
  if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("bind");
    close(soc);
    return (-1);
  }

  // NOTE: フラグを書き変えて自分宛て以外のパケットも受信対象にする
  if_req.ifr_flags = if_req.ifr_flags | IFF_PROMISC | IFF_UP;

  if (ioctl(soc, SIOCSIFFLAGS, &if_req) < 0) {
    perror("ioctl");
    close(soc);
    return (-1);
  }

  return (soc);
}
