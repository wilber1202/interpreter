#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#define _GNU_SOURCE
#define LOGIN_SIZE_1024     1024
#define LOGIN_LOG_INTERVAL  300

unsigned long   g_login_success_num = 0;
unsigned long   g_login_fail_num = 0;
unsigned long   g_login_error[20] = {0};
char    *g_login_success_reply = "HTTP/1.1 200 OK\r\n"
                                "Server: www.introbao.com:8000\r\n"
                                "Cache-Control: no-cache\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: 7\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "success";
char    *g_login_fail_reply    = "HTTP/1.1 200 OK\r\n"
                                "Server: www.introbao.com:8000\r\n"
                                "Cache-Control: no-cache\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: 4\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "fail";

void reply(int sock, char *post) {
    int ret;
    char *body;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    (void)getpeername(sock, (struct sockaddr *)&addr, &addrlen);

    body = strstr(post, "\r\n\r\n");
    if (NULL == body) {
        (void)__sync_fetch_and_add(&g_login_error[4], 1);
        syslog(LOG_ERR, "do not receive http body\n");
        goto fail;
    }

    if (NULL == strstr(body, "user=admin")) {
        (void)__sync_fetch_and_add(&g_login_error[5], 1);
        syslog(LOG_ERR, "user error\n");
        goto fail;
    }

    if (NULL == strstr(body, "passwd=introbao")) {
        (void)__sync_fetch_and_add(&g_login_error[6], 1);
        syslog(LOG_ERR, "passwd error\n");
        goto fail;
    }

    if (NULL == strstr(body, "groupid=")) {
        (void)__sync_fetch_and_add(&g_login_error[7], 1);
        syslog(LOG_ERR, "groupid error\n");
        goto fail;
    }

    (void)__sync_fetch_and_add(&g_login_success_num, 1);

    ret = send(sock, g_login_success_reply, strlen(g_login_success_reply), 0);
    if (ret < 0) {
        (void)__sync_fetch_and_add(&g_login_error[8], 1);
        syslog(LOG_ERR, "send error, %s\n", strerror(errno));
    }

    syslog(LOG_NOTICE, "ip: %s, port: %d, login success\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return;

fail:
    (void)__sync_fetch_and_add(&g_login_fail_num, 1);

    ret = send(sock, g_login_fail_reply, strlen(g_login_fail_reply), 0);
    if (ret < 0) {
        (void)__sync_fetch_and_add(&g_login_error[9], 1);
        syslog(LOG_ERR, "send error, %s\n", strerror(errno));
    }

    syslog(LOG_NOTICE, "ip: %s, port: %d, login fail\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return;
}

void *thread_login(void *arg) {
    char recv_buf[LOGIN_SIZE_1024] = {0};
    int recvd;
    int recv_sock = (int)(long)arg;
    struct timeval  timeout = {7, 0};

    (void)prctl(PR_SET_NAME, "login_recv");

    (void)setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (1) {
        recvd = recv(recv_sock, recv_buf, LOGIN_SIZE_1024, 0);
        if (0 == recvd) {
            (void)__sync_fetch_and_add(&g_login_error[1], 1);
            syslog(LOG_ERR, "recv zero, %s\n", strerror(errno));
            break;
        } else if (recvd < 0) {
            if ((EAGAIN == errno) || (EINTR == errno) || (EWOULDBLOCK == errno)) {
                (void)__sync_fetch_and_add(&g_login_error[2], 1);
                syslog(LOG_ERR, "recv eagain, %s\n", strerror(errno));

                (void)sleep(2);
                continue;
            } else {
                (void)__sync_fetch_and_add(&g_login_error[3], 1);
                syslog(LOG_ERR, "recv error, %s\n", strerror(errno));
                break;
            }
        }

        reply(recv_sock, recv_buf);
    }

    close(recv_sock);

    return NULL;
}

void *thread_syslog(void *arg) {
    time_t cur_s, last_log = 0;

    (void)arg;
    (void)prctl(PR_SET_NAME, "login_syslog");

    while (1) {
        (void)sleep(1);

        cur_s = time(NULL);
        if (cur_s - last_log > LOGIN_LOG_INTERVAL) {
            last_log = cur_s - cur_s % LOGIN_LOG_INTERVAL;
            syslog(LOG_NOTICE, "[RUN] login success: %lu, login fail: %lu, error: %lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu\n",
                    g_login_success_num, g_login_fail_num, g_login_error[0], g_login_error[1], g_login_error[2], g_login_error[3],
                    g_login_error[4], g_login_error[5], g_login_error[6], g_login_error[7], g_login_error[8], g_login_error[9]);
        }
    }
}


int main(int argc, char *argv[]) {
    int sock_fd;
    int listen_fd;
    int optval = 0;
    pthread_t   id;
    pthread_attr_t  attr;
    struct sockaddr_in addr;
    struct sigaction sa = {.sa_handler =  SIG_IGN,};

    (void)sigaction(SIGPIPE, &sa, 0);

    (void)pthread_attr_init(&attr);
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval));

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(8000);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)(void *)&addr, sizeof(struct sockaddr_in)) < 0) {
        syslog(LOG_ERR, "bind error, %s\n", strerror(errno));
        return -1;
    }

    if (listen(listen_fd , 0) < 0) {
        syslog(LOG_ERR, "listen error, %s\n", strerror(errno));
        return -1;
    }

    (void)pthread_create(&id, NULL, thread_syslog, NULL);

    syslog(LOG_INFO, "interpreter login start\n");

    while (1) {
        sock_fd = accept(listen_fd, NULL, NULL);
        if (sock_fd < 0) {
            g_login_error[0]++;
            continue;
        }

        (void)pthread_create(&id, &attr, thread_login, (void *)(long)sock_fd);
    }

}

