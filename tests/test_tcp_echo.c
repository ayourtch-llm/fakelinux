#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

/*
 * TCP echo test: fork child as echo server, parent as client.
 * Uses port 0 (kernel picks available port), communicates port via pipe.
 * Uses libc wrappers — musl will call our emulated syscalls.
 */

int main(void) {
    int pipefd[2];
    int status;
    pid_t pid;

    printf("TEST: TCP echo (fork server/client)\n");

    if (pipe(pipefd) < 0) {
        printf("FAIL: pipe() failed\n");
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        printf("FAIL: fork() failed\n");
        return 1;
    }

    if (pid == 0) {
        /* ---- CHILD: echo server ---- */
        close(pipefd[0]); /* close read end */

        int srv = socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) {
            printf("FAIL: server socket() failed\n");
            _exit(1);
        }

        int one = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; /* kernel picks port */

        if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            printf("FAIL: bind() failed\n");
            _exit(1);
        }

        /* Get assigned port */
        socklen_t alen = sizeof(addr);
        if (getsockname(srv, (struct sockaddr *)&addr, &alen) < 0) {
            printf("FAIL: getsockname() failed\n");
            _exit(1);
        }
        unsigned short port = ntohs(addr.sin_port);
        printf("  server: bound to port %d\n", port);

        if (listen(srv, 1) < 0) {
            printf("FAIL: listen() failed\n");
            _exit(1);
        }

        /* Send port to parent via pipe */
        write(pipefd[1], &port, sizeof(port));
        close(pipefd[1]);

        /* Accept one connection */
        int client = accept(srv, NULL, NULL);
        if (client < 0) {
            printf("FAIL: accept() failed\n");
            _exit(1);
        }
        printf("  server: accepted connection\n");

        /* Echo loop: read then write back */
        char buf[256];
        ssize_t n = read(client, buf, sizeof(buf));
        if (n > 0) {
            write(client, buf, n);
        }

        close(client);
        close(srv);
        _exit(0);
    }

    /* ---- PARENT: client ---- */
    close(pipefd[1]); /* close write end */

    /* Read port from child */
    unsigned short port;
    if (read(pipefd[0], &port, sizeof(port)) != sizeof(port)) {
        printf("FAIL: reading port from pipe failed\n");
        return 1;
    }
    close(pipefd[0]);
    printf("  client: server port is %d\n", port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("FAIL: client socket() failed\n");
        return 1;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        printf("FAIL: connect() failed\n");
        return 1;
    }
    printf("  client: connected\n");

    const char *msg = "HELLO";
    if (write(sock, msg, 5) != 5) {
        printf("FAIL: write() failed\n");
        return 1;
    }

    char buf[256];
    ssize_t n = read(sock, buf, sizeof(buf));
    if (n != 5 || memcmp(buf, "HELLO", 5) != 0) {
        printf("FAIL: echo mismatch (got %zd bytes)\n", n);
        return 1;
    }
    printf("  client: received echo '%.*s'\n", (int)n, buf);

    close(sock);

    /* Wait for child */
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAIL: child exited with status %d\n", WEXITSTATUS(status));
        return 1;
    }

    printf("PASS: TCP echo works correctly\n");
    return 0;
}
