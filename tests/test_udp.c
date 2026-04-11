#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * UDP test: two sockets on localhost, sendto/recvfrom.
 * Uses port 0 (kernel picks), getsockname to discover it.
 */

int main(void) {
    printf("TEST: UDP sendto/recvfrom\n");

    /* Create receiver socket */
    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) {
        printf("FAIL: recv socket() failed\n");
        return 1;
    }

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    recv_addr.sin_port = 0;

    if (bind(recv_sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        printf("FAIL: bind() failed\n");
        return 1;
    }

    /* Get assigned port */
    socklen_t alen = sizeof(recv_addr);
    if (getsockname(recv_sock, (struct sockaddr *)&recv_addr, &alen) < 0) {
        printf("FAIL: getsockname() failed\n");
        return 1;
    }
    unsigned short port = ntohs(recv_addr.sin_port);
    printf("  receiver bound to port %d\n", port);

    /* Create sender socket */
    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) {
        printf("FAIL: send socket() failed\n");
        return 1;
    }

    /* Send data */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest.sin_port = htons(port);

    const char *msg = "UDP_TEST";
    ssize_t sent = sendto(send_sock, msg, strlen(msg), 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent != (ssize_t)strlen(msg)) {
        printf("FAIL: sendto returned %zd\n", sent);
        return 1;
    }
    printf("  sent %zd bytes\n", sent);

    /* Receive data */
    char buf[256];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    ssize_t recvd = recvfrom(recv_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from_addr, &from_len);
    if (recvd != (ssize_t)strlen(msg)) {
        printf("FAIL: recvfrom returned %zd\n", recvd);
        return 1;
    }
    if (memcmp(buf, "UDP_TEST", 8) != 0) {
        printf("FAIL: data mismatch\n");
        return 1;
    }
    printf("  received %zd bytes: '%.*s'\n", recvd, (int)recvd, buf);

    close(send_sock);
    close(recv_sock);

    printf("PASS: UDP sendto/recvfrom works correctly\n");
    return 0;
}
