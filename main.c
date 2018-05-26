#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arp.h"
#include "cmd.h"
#include "ether.h"
#include "ip.h"
#include "param.h"
#include "sock.h"

int EndFlag = 0;

int DeviceSoc;

PARAM Param;

/*
 * SEthTread
 * 標準入力を poll() で監視して, 読み込み可能になったら fgets() で読む
 */
void *SEthThread(void *arg) {
    int nready;
    struct pollfd targets[1];
    u_int8_t buf[2048];
    int len;

    targets[0].fd = DeviceSoc;
    targets[0].events = POLLIN | POLLERR;

    while (EndFlag == 0) {
        switch ((nready = poll(targets, 1, 1000))) {
            case -1:
                if (errno != EINTR) {
                    perror("poll");
                }
                break;
            case 0:
                break;
            default:
                if (targets[0].revents & (POLLIN | POLLERR)) {
                    if ((len = read(DeviceSoc, buf, sizeof(buf))) <= 0) {
                        perror("read");
                    } else {
                        EtherRecv(DeviceSoc, buf, len);
                    }
                }
                break;
        }
    }

    return (NULL);
}

void *StdInThread(void *arg) {
    int nready;
    struct pollfd targets[1];
    char buf[2048];

    // NOTE: 関数 fileno() は、引数 stream を調べ、その整数のディスクリプターを返す。
    targets[0].fd = fileno(stdin);
    targets[0].events = POLLIN, POLLERR;

    while (EndFlag == 0) {
        switch ((nready = poll(targets, 1, 1000))) {
            case -1:
                if (errno != EINTR) {
                    perror("poll");
                }
                break;
            case 0:
                break;
            default:
                if (targets[0].revents & (POLLIN | POLLERR)) {
                    fgets(buf, sizeof(buf), stdin);
                    DoCmd(buf);
                }
                break;
        }
    }

    return (NULL);
}

/*
 * sig_term
 * 各スレッドが EndFlag を見ていて，0以外になるとスレッドを抜けるようになっている
 */
void sig_term(int sig) {
    EndFlag = 1;
}

/*
 * ending
 * EndFlagが1になったらmainから呼ばれる.
 * DeviceSocのプロミスキャストモードを解除して，
 * ファイルディスクリプタをクローズする
 */
int ending() {
    struct ifreq if_req;

    printf("ending\n");

    if (DeviceSoc != -1) {
        strcpy(if_req.ifr_name, Param.device);
        if (ioctl(DeviceSoc, SIOCGIFFLAGS, &if_req) < 0) {
            perror("ioctl");
        }

        if_req.ifr_flags = if_req.ifr_flags & ~(IFF_PROMISC);
        if (ioctl(DeviceSoc, SIOCGIFFLAGS, &if_req) < 0) {
            perror("ioctl");
        }

        close(DeviceSoc);
        DeviceSoc = -1;
    }

    return (0);
}

/*
 * show_ifreq
 * mainから実行され，指定したデバイス名の情報を出力する．
 *
 */
int show_ifreq(char *name) {
    char buf1[80];
    int soc;
    struct ifreq ifreq;
    struct sockaddr_in addr;

    if ((soc = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return (-1);
    }

    strcpy(ifreq.ifr_name, name);

    /* NOTE: SIOCGIFFLAGS デバイスの active フラグワード
    *  デバイスフラグ
    *  IFF_UP	インターフェースは動作中。
    *  IFF_BROADCAST	有効なブロードキャストアドレスがセットされている。
    *  IFF_PROMISC	インターフェースは promiscuous モードである。
    *  IFF_MULTICAST	マルチキャストをサポートしている。
    *  IFF_LOOPBACK	インターフェースはループバックである。
    *  IFF_POINTOPOINT	インターフェースは point-to-point リンクである。
    */
    if (ioctl(soc, SIOCGIFFLAGS, &ifreq) == -1) {
        perror("ioctl:flags");
        close(soc);
        return (-1);
    }

    if (ifreq.ifr_flags & IFF_UP) printf("UP ");
    if (ifreq.ifr_flags & IFF_BROADCAST) printf("BROADCAST ");
    if (ifreq.ifr_flags & IFF_PROMISC) printf("PROMISC ");
    if (ifreq.ifr_flags & IFF_MULTICAST) printf("MULTICAST ");
    if (ifreq.ifr_flags & IFF_LOOPBACK) printf("LOOPBACK");
    if (ifreq.ifr_flags & IFF_POINTOPOINT) printf("P2P ");
    printf("\n");

    // NOTE: デバイスの MTU (Maximum Transfer Unit)
    if (ioctl(soc, SIOCGIFMTU, &ifreq) == -1) {
        perror("ioctl:mtu");
    } else {
        printf("mtu=%d\n", ifreq.ifr_mtu);
    }

    // NOTE: デバイスのアドレス
    if (ioctl(soc, SIOCGIFADDR, &ifreq) == -1) {
        perror("ioctl:addr");
    } else if (ifreq.ifr_addr.sa_family != AF_INET) {
        printf("not AF_INET\n");
    } else {
        /* NOTE:
         * void *memcpy(void *dest, const void *src, size_t n);
         * memcpy() はメモリー領域 src の先頭 n バイトを メモリー領域 dest にコピーする。コピー元の領域と コピー先の領域が重なってはならない。
         */
        memcpy(&addr, &ifreq.ifr_addr, sizeof(struct sockaddr_in));

        // NOTE: `inet_ntop` IPv4/IPv6 アドレスをバイナリ形式からテキスト形式に変換する
        printf("myip=%s\n", inet_ntop(AF_INET, &addr.sin_addr, buf1, sizeof(buf1)));
        Param.myip = addr.sin_addr;
    }

    close(soc);

    if (GetMacAddress(name, Param.mymac) == -1) {
        printf("GetMacAddress:error");
    } else {
        printf("mymac=%s\n", sether_ntoa_r(Param.mymac, buf1));
    }

    return (0);
}

int main(int argc, char *argv[]) {
    char buf1[80];
    int paramFlag;
    pthread_attr_t attr;
    pthread_t thread_id;

    SetDefaultParam();

    paramFlag = 0;

    for (int i = 0; i < argc; i++) {
        if (ReadParam(argv[1]) == -1) {
            exit(-1);
        }

        paramFlag = 1;
    }

    if (paramFlag == 0) {
        if (ReadParam("./SEth.ini") == -1) {
            exit(-1);
        }
    }

    printf("IP-TTL=%d\n", Param.IpTTL);
    printf("MTU=%d\n", Param.MTU);

    srandom(time(NULL));

    IpRecvBufInit();

    if ((DeviceSoc == init_socket(Param.device)) == -1) {
        exit(-1);
    }

    printf("device=%s\n", Param.device);
    printf("++++++++++++++++++++++++\n");
    show_ifreq(Param.device);
    printf("++++++++++++++++++++++++\n");

    printf("vmac=%s\n", sether_ntoa_r(Param.vmac, buf1));
    printf("vip=%s\n", inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)));
    printf("vmask=%s\n", inet_ntop(AF_INET, &Param.vmask, buf1, sizeof(buf1)));
    printf("gateway=%s\n", inet_ntop(AF_INET, &Param.gateway, buf1, sizeof(buf1)));

    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);
    signal(SIGQUIT, sig_term);
    signal(SIGPIPE, SIG_IGN);

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 102400);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&thread_id, &attr, SEthThread, NULL) != 0) {
        printf("pthread_create:error\n");
    }

    if (pthread_create(&thread_id, &attr, StdInThread, NULL) != 0) {
        printf("pthread_create:error\n");
    }

    if (ArpCheckGArp(DeviceSoc) == 0) {
        printf("GArp check fail\n");
        return (-1);
    }

    while (EndFlag == 0) {
        sleep(1);
    }

    ending();

    return (0);
}
