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
#include "md5.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#define CHECK_SIZE_128      128
#define CHECK_SIZE_1024     1024
#define CHECK_LOG_INTERVAL  300
#define MD5_SIZE		    16
#define MD5_STR_LEN		    (MD5_SIZE * 2)
#define FILE_DIRECTORY      "/tmp/%d/"

unsigned long   g_check_success_num = 0;
unsigned long   g_check_fail_num = 0;
unsigned long   g_check_error[20] = {0};
char    *g_check_success_reply = "HTTP/1.1 200 OK\r\n"
                                "Server: www.introbao.com:8001\r\n"
                                "Cache-Control: no-cache\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %d\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s";
char    *g_check_fail_reply    = "HTTP/1.1 200 OK\r\n"
                                "Server: www.introbao.com:8001\r\n"
                                "Cache-Control: no-cache\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: 17\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "{\"totalnumber\":0}";
char    *g_check_uri           = "/checkvideo.html?groupid=";
char    *g_file_list           = "{"
                    			"\"name\": \"%s\","
                    			"\"checksum\": \"%s\""
                    		    "}";
char    *g_json_head           = "{"
                                "\"totalnumber\": %d,"
                                "\"list\": [";
char    *g_json_tail           = "]}";

int generate_md5(const char *file_path, char *md5_str)
{
	int i;
	int fd;
	int ret;
	MD5_CTX md5;
	unsigned char data[CHECK_SIZE_1024];
	unsigned char md5_value[MD5_SIZE];

	fd = open(file_path, O_RDONLY);
	if (-1 == fd) {
		return -1;
	}

	MD5Init(&md5);

	while (1) {
		ret = read(fd, data, CHECK_SIZE_1024);
		if (-1 == ret) {
			return -1;
		}

		MD5Update(&md5, data, ret);

		if (0 == ret || ret < CHECK_SIZE_1024) {
			break;
		}
	}

	close(fd);

	MD5Final(&md5, md5_value);

	for(i = 0; i < MD5_SIZE; i++) {
		snprintf(md5_str + i*2, 2 + 1, "%02x", md5_value[i]);
	}

	md5_str[MD5_STR_LEN] = '\0';

	return 0;
}

void format_list(char *name, char *md5, char *list) {
    int len = 0;

    len = strlen(list);

    if (0 != len) {
        list[len] = ',';
        len++;
    }

    sprintf(list + len, g_file_list, name, md5);
    return;
}

void format_response(int num, char *list, char *reply) {
    int len = 0;
    char json[CHECK_SIZE_1024] = {0};

    sprintf(json, g_json_head, num);

    len = strlen(json);
    memcpy(json + len, list, strlen(list));

    len = strlen(json);
    memcpy(json + len, g_json_tail, strlen(g_json_tail));

    sprintf(reply, g_check_success_reply, strlen(json), json);

    return;
}

int read_file(int id, char *reply) {
    DIR *dirp;
    int file_num = 0;
    struct dirent *dp = NULL;
    char path[CHECK_SIZE_128] = {0};
    char md5_str[MD5_STR_LEN + 1] = {0};
    char file_list[CHECK_SIZE_1024] = {0};

    sprintf(path, FILE_DIRECTORY, id);

    dirp = opendir(path);
    if (NULL == dirp) {
        return -1;
    }

    while (NULL != (dp = readdir(dirp))) {
        if ((0 == strcmp(dp->d_name, ".")) || (0 == strcmp(dp->d_name, ".."))) {
            continue;
        }

        if (0 != strcmp(dp->d_name + strlen(dp->d_name) - 3, "avi")) {
            continue;
        }

        memcpy(path + strlen(path), dp->d_name, strlen(dp->d_name));

        generate_md5(path, md5_str);

        file_num++;
        format_list(dp->d_name, md5_str, file_list);

        memset(md5_str, 0, MD5_STR_LEN);
        memset(path, 0, CHECK_SIZE_128);
        sprintf(path, FILE_DIRECTORY, id);
    }

    format_response(file_num, file_list, reply);

    closedir(dirp);

    return 0;
}

void reply(int sock, char *get) {
    int ret;
    int id=9999;
    char *pgroupid;
    struct sockaddr_in addr;
    char reply[CHECK_SIZE_1024] = {0};
    socklen_t addrlen = sizeof(addr);

    (void)getpeername(sock, (struct sockaddr *)&addr, &addrlen);

    pgroupid = strstr(get, g_check_uri);
    if (NULL == pgroupid) {
        (void)__sync_fetch_and_add(&g_check_error[4], 1);
        syslog(LOG_ERR, "check video request is abnormal\n");
        goto fail;
    }

    pgroupid += strlen(g_check_uri);
    sscanf(pgroupid, "%d", &id);

    if (9999 == id) {
        (void)__sync_fetch_and_add(&g_check_error[5], 1);
        syslog(LOG_ERR, "check video groupid is abnormal\n");
        goto fail;
    }

    ret = read_file(id, reply);
    if (ret < 0) {
        (void)__sync_fetch_and_add(&g_check_error[6], 1);
        syslog(LOG_ERR, "generate_md5 fail\n");
        goto fail;
    }

    (void)__sync_fetch_and_add(&g_check_success_num, 1);

    ret = send(sock, reply, strlen(reply), 0);
    if (ret < 0) {
        (void)__sync_fetch_and_add(&g_check_error[7], 1);
        syslog(LOG_ERR, "send error, %s\n", strerror(errno));
    }

    syslog(LOG_NOTICE, "ip: %s, port: %d, check version success\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return;

fail:
    (void)__sync_fetch_and_add(&g_check_fail_num, 1);

    ret = send(sock, g_check_fail_reply, strlen(g_check_fail_reply), 0);
    if (ret < 0) {
        (void)__sync_fetch_and_add(&g_check_error[8], 1);
        syslog(LOG_ERR, "send error, %s\n", strerror(errno));
    }

    syslog(LOG_NOTICE, "ip: %s, port: %d, check version fail\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return;
}

void *thread_check(void *arg) {
    char recv_buf[CHECK_SIZE_1024] = {0};
    int recvd;
    int recv_sock = (int)(long)arg;
    struct timeval  timeout = {7, 0};

    (void)prctl(PR_SET_NAME, "check_recv");

    (void)setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    while (1) {
        recvd = recv(recv_sock, recv_buf, CHECK_SIZE_1024, 0);
        if (0 == recvd) {
            (void)__sync_fetch_and_add(&g_check_error[1], 1);
            syslog(LOG_ERR, "recv zero, %s\n", strerror(errno));
            break;
        } else if (recvd < 0) {
            if ((EAGAIN == errno) || (EINTR == errno) || (EWOULDBLOCK == errno)) {
                (void)__sync_fetch_and_add(&g_check_error[2], 1);
                syslog(LOG_ERR, "recv eagain, %s\n", strerror(errno));

                (void)sleep(2);
                continue;
            } else {
                (void)__sync_fetch_and_add(&g_check_error[3], 1);
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
    (void)prctl(PR_SET_NAME, "check_syslog");

    while (1) {
        (void)sleep(1);

        cur_s = time(NULL);
        if (cur_s - last_log > CHECK_LOG_INTERVAL) {
            last_log = cur_s - cur_s % CHECK_LOG_INTERVAL;
            syslog(LOG_NOTICE, "[RUN] check success: %lu, check fail: %lu, error: %lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu/%lu\n",
                    g_check_success_num, g_check_fail_num, g_check_error[0], g_check_error[1], g_check_error[2], g_check_error[3],
                    g_check_error[4], g_check_error[5], g_check_error[6], g_check_error[7], g_check_error[8], g_check_error[9]);
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
    addr.sin_port   = htons(8001);
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

    syslog(LOG_INFO, "interpreter check video start\n");

    while (1) {
        sock_fd = accept(listen_fd, NULL, NULL);
        if (sock_fd < 0) {
            g_check_error[0]++;
            continue;
        }

        (void)pthread_create(&id, &attr, thread_check, (void *)(long)sock_fd);
    }
}

