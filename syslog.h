#ifndef __SYSLOG_H__
#define __SYSLOG_H__


#define SYSLOG_MSG_LEN		 	 1024			/* RFC3164 */
#define SYSLOG_TAG_LEN			 32
#define SYSLOG_ERROR_CNT_LEN     16

#define LOG_EMERG   0  /* system is unusable */
#define LOG_ALERT   1  /* action must be taken immediately */
#define LOG_CRIT    2   /* critical conditions */
#define LOG_ERR     3   /* error conditions */
#define LOG_WARNING 4 /* warning conditions */
#define LOG_NOTICE  5  /* normal but significant condition */
#define LOG_INFO    6    /* informational */
#define LOG_DEBUG   7   /* debug-level messages */
#define LOG_KERNEL				 0x0008			/* priority between 0~7 */
#define LOG_SOCKET				 "/dev/shm/beaver_log"

extern char *__progname;

static int unix_fd = -1;
static struct sockaddr_un addr = {0};

/***************************************
       syslog 初始化函数
****************************************/
static int syslog_init(void){
	if(unix_fd >= 0)
		return 0;
	
	addr.sun_family = AF_UNIX;
	(void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%c%s", '\0', LOG_SOCKET);
	unix_fd = socket(AF_UNIX, SOCK_DGRAM, 0);	
	if(unix_fd >= 0) 
		return 0;
	return -1;
}

/***************************************
       syslog 使用前必须调用初始化接口，
       否则syslog功能无效
****************************************/
static void syslog(int priority, const char *message, ...)
{
	char buf[SYSLOG_MSG_LEN] = {0}, *name = buf+sizeof(long), *msg = buf+sizeof(long)+SYSLOG_TAG_LEN;
	int i;
	static unsigned long ulErrCnt = 0;
	va_list args = {0};

	if(unix_fd < 0){
		return;
	}

	*(unsigned long *)buf = ulErrCnt;
	if(priority != LOG_KERNEL) snprintf(name, SYSLOG_TAG_LEN + SYSLOG_ERROR_CNT_LEN, "%s", __progname); /* 一般情况下beaver不关心PRI */
	else snprintf(name, SYSLOG_TAG_LEN + SYSLOG_ERROR_CNT_LEN, "%s", "kernel");
	va_start(args, message);
	int len = vsnprintf(msg, sizeof(buf)-64, message, args);
	va_end(args);

	if(len > (int)(sizeof(buf)-64-1)) len = (int)sizeof(buf)-64-1;
	for(i = 0; i < len; i++)
		if(msg[i] == '\n') msg[i] = ' ';
	len += sizeof(long) + SYSLOG_TAG_LEN + SYSLOG_ERROR_CNT_LEN + 1;
	if(0 > sendto(unix_fd, buf, len, MSG_DONTWAIT, (void *)&addr, sizeof(addr))){ /* 不能阻塞 */
		__sync_fetch_and_add(&ulErrCnt,1);
	}
}

#endif


