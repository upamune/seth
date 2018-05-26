//
// Created by serizawa on 18/05/26.
//

#include "param.h"
#include "ether.h"
#include "sock.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// NOTE: 宣言だけを行い定義は行わない宣言方法
extern PARAM Param;

static char *ParamFname = NULL;

/*
 * SetDefaultParam
 * 設定されない場合でも正しく動作するように，デフォルト値を入れる
 */
int SetDefaultParam() {
  Param.MTU = DEFAULT_MTU;
  Param.IpTTL = DEFAULT_IP_TTL;

  return (0);
}

/*
 * ReadParam
 * 設定をiniファイルから読んでParam構造体に格納する
 */
int ReadParam(char *fname) {
  FILE *fp;
  char buf[1024];
  char *ptr, *saveptr;

  ParamFname = fname;

  if ((fp = fopen(fname, "r")) == NULL) {
    printf("%s cannot read\n", fname);
    return (-1);
  }

  while (1) {
    fgets(buf, sizeof(buf), fp);

    // NOTE: 関数 feof() は stream で示されるストリームの EOF 指示子をテストし、
    // セットされていれば 0 以外の数を返す。
    if (feof(fp))
      break;

    // NOTE: strtok() 関数は文字列を 0 個以上の空でないトークンの列に分割する
    // 第2引数がdelimiter
    ptr = strtok_r(buf, "=", &saveptr);
    if (ptr != NULL) {
      if (strcmp(ptr, "IP-TTL") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.IpTTL = atoi(ptr);
        }
      } else if (strcmp(ptr, "MTU") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.MTU = atoi(ptr);
          if (Param.MTU > ETHERMTU) {
            printf("ReadParam:MTU(%d) <= ETHERMTU(%d)\n", Param.MTU, ETHERMTU);
            Param.MTU = ETHERMTU;
          }
        }
      } else if (strcmp(ptr, "gateway") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.gateway.s_addr = inet_addr(ptr);
        }
      } else if (strcmp(ptr, "device") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.device = strdup(ptr);
        }
      } else if (strcmp(ptr, "vmac") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          sether_aton(ptr, Param.vmac);
        }
      } else if (strcmp(ptr, "vip") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.vip.s_addr = inet_addr(ptr);
        }
      } else if (strcmp(ptr, "vmask") == 0) {
        if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
          Param.vmask.s_addr = inet_addr(ptr);
        }
      }
    }
  }

  fclose(fp);

  return (0);
}

int isTargetIPAddr(struct in_addr *addr) {
  if (Param.vip.s_addr == addr->s_addr) {
    return (1);
  }

  return (0);
}

int isSameSubnet(struct in_addr *addr) {
  if ((addr->s_addr & Param.vmask.s_addr) ==
      (Param.vip.s_addr & Param.vmask.s_addr)) {
    return (1);
  }
  return (0);
}
