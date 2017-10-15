/*
 *功能需求：
 *1、数据网络准备就绪后，连接https后台
 *2、连接成功后，每隔20秒钟发送一次GET命令到后台
 *3、与后台保持长连接，断开后主动再去重连，连接成功仍然按照第2条发送数据
 *4、收到后台的数据时，在rcv函数中打印出来
 *测试时请搭建自己的服务器
 *此例子为长连接，只要是软件上能够检测到的网络异常，可以自动去重新连接
 */
#include "string.h"
#include "iot_os.h"
#include "iot_debug.h"
#include "iot_network.h"
#include "iot_socket.h"
#include "iot_fs.h"
#include "iot_flash.h"
#include "iot_types.h"
#include "ssllib.h"
typedef struct {
    UINT8 Type;
    UINT8 Data;
}USER_MESSAGE;

enum
{
	USER_MSG_NETWORK,
	USER_MSG_TIMER,
};

extern T_AMOPENAT_INTERFACE_VTBL* g_s_InterfaceVtbl;
#define DBG_INFO(X, Y...)	iot_debug_print("%s %d:"X, __FUNCTION__, __LINE__, ##Y)
#define DBG_ERROR(X, Y...)	iot_debug_print("%s %d:"X, __FUNCTION__, __LINE__, ##Y)

#define SOCKET_CLOSE(A)         if (A >= 0) {close(A);A = -1;}
#define TEST_IP						"36.7.87.100"
//#define TEST_URL
#define TEST_PORT					(4433)
#define TEST_DATA					"GET / HTTP/1.1\r\nHost: 36.7.87.100\r\nConnection: keep-alive\r\n\r\n"
#define SSL_RECONNECT_MAX			(8)
#define SSL_HEAT_TO					20
#define SSL_FILE_PATH 				L"/ldata/ca_crt.mp3"
static HANDLE hTimer;
static HANDLE hSocketTask;
static E_OPENAT_NETWORK_STATE NWState;				//网络状态
static uint8_t ToFlag = 0;
const char *DEMO_CA_CERT = "-----BEGIN CERTIFICATE-----\r\n"\
		"MIIDnDCCAwWgAwIBAgIJAMHOdn3g57i0MA0GCSqGSIb3DQEBBQUAMIGRMQswCQYD\r\n"\
		"VQQGEwJDTjERMA8GA1UECBMIU2hhbmdIYWkxETAPBgNVBAcTCFNoYW5nSGFpMQ8w\r\n"\
		"DQYDVQQKEwZBSVJNMk0xDTALBgNVBAsTBFNPRlQxFjAUBgNVBAMTDXpodXRpYW5o\r\n"\
		"dWEtY2ExJDAiBgkqhkiG9w0BCQEWFXpodXRpYW5odWFAYWlybTJtLmNvbTAeFw0x\r\n"\
		"NzA3MjEwNDEwMzBaFw0xODA3MjEwNDEwMzBaMIGRMQswCQYDVQQGEwJDTjERMA8G\r\n"\
		"A1UECBMIU2hhbmdIYWkxETAPBgNVBAcTCFNoYW5nSGFpMQ8wDQYDVQQKEwZBSVJN\r\n"\
		"Mk0xDTALBgNVBAsTBFNPRlQxFjAUBgNVBAMTDXpodXRpYW5odWEtY2ExJDAiBgkq\r\n"\
		"hkiG9w0BCQEWFXpodXRpYW5odWFAYWlybTJtLmNvbTCBnzANBgkqhkiG9w0BAQEF\r\n"\
		"AAOBjQAwgYkCgYEAvRGzRy4RWO1XhFaB8uXd1F7cfTxW18coyY2aNnOrwrnQAU5F\r\n"\
		"mIXL7L076Rl7aOXi2oCiaYt1jKehXIuLJ9Mho9dW/Iid7dpA7n7guzvesEpuciy5\r\n"\
		"wc4zJOscU9V/M373FwVGBTbyoP4hgGu4LNBu2AyJ6EYgsqAsd/FGNArZTXsCAwEA\r\n"\
		"AaOB+TCB9jAdBgNVHQ4EFgQUHqGE6j7NmQ5blERny6vIRDDicRowgcYGA1UdIwSB\r\n"\
		"vjCBu4AUHqGE6j7NmQ5blERny6vIRDDicRqhgZekgZQwgZExCzAJBgNVBAYTAkNO\r\n"\
		"MREwDwYDVQQIEwhTaGFuZ0hhaTERMA8GA1UEBxMIU2hhbmdIYWkxDzANBgNVBAoT\r\n"\
		"BkFJUk0yTTENMAsGA1UECxMEU09GVDEWMBQGA1UEAxMNemh1dGlhbmh1YS1jYTEk\r\n"\
		"MCIGCSqGSIb3DQEJARYVemh1dGlhbmh1YUBhaXJtMm0uY29tggkAwc52feDnuLQw\r\n"\
		"DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQAvjFrd/VyydXeaBjuJbJHR\r\n"\
		"H2gLli0w5JQ3FbBpEZBlbpvVL4nmonkrCl9Y77lLSTpAN2E3IVJyE7aU2wbPTjJq\r\n"\
		"qnk0oLPEIkMh26JtnmSNZLmHlTsqpJvlDhH+Rg+vrrUSGZrZIWm+ObhUe0CRxRcH\r\n"\
		"qPAObM42B+GqVaIK3ZPB8w==\r\n-----END CERTIFICATE-----\r\n";


#ifdef TEST_URL
static uint32_t SSL_Gethostbyname(void)
{
    //域名解析
	ip_addr_t *IP;
    struct hostent *hostentP = NULL;
    char *ipAddr = NULL;

    //获取域名ip信息
    hostentP = gethostbyname(TEST_URL);

    if (!hostentP)
    {
        DBG_ERROR("gethostbyname %s fail", TEST_URL);
        return 0;
    }

    // 将ip转换成字符串
    ipAddr = ipaddr_ntoa((const ip_addr_t *)hostentP->h_addr_list[0]);

    DBG_ERROR("gethostbyname %s ip %s", TEST_URL, ipAddr);
    IP = (ip_addr_t *)hostentP->h_addr_list[0];
    return IP->addr;
}
#endif
static int32_t Socket_ConnectServer(void)
{
    int connErr;
    struct sockaddr_in TCPServerAddr;
	int32_t Socketfd;
#ifdef TEST_URL
	uint32_t IP;
	IP = SSL_Gethostbyname();
#endif


#ifdef TEST_URL
	if (IP)
#else
	if (1)
#endif
	{
		Socketfd = socket(AF_INET,SOCK_STREAM,0);
	    if (Socketfd < 0)
	    {
	        DBG_ERROR("create tcp socket error");
	        return -1;
	    }
	    // 建立TCP链接
	    memset(&TCPServerAddr, 0, sizeof(TCPServerAddr)); // 初始化服务器地址
	    TCPServerAddr.sin_family = AF_INET;
	    TCPServerAddr.sin_port = htons((unsigned short)TEST_PORT);
#ifndef TEST_URL
	    inet_aton(TEST_IP, &TCPServerAddr.sin_addr);
#endif
#ifdef TEST_URL
	    TCPServerAddr.sin_addr.s_addr = IP;
#else
	    DBG_INFO("%08x", TCPServerAddr.sin_addr.s_addr);
#endif
	    connErr = connect(Socketfd, (const struct sockaddr *)&TCPServerAddr, sizeof(struct sockaddr));
	    if (connErr < 0)
	    {
	    	DBG_ERROR("tcp connect error %d", socket_errno(Socketfd));
	        close(Socketfd);
	        return -1;
	    }
	    DBG_INFO("[socket] tcp connect success");
	    return Socketfd;
	}
	else
	{
		return -1;
	}
}

/**
 * @brief 发送SSL封装好的数据，如果使用socket编程的，可以直接参考，如果使用AT指令编程的，那么需要自己来实现
 * @param Socketfd [in] socket id，如果是AT指令，单路链接，传入0，不用管，多路链接的，传入CIPSTART时用的通道号
 * @param Buf [in] 需要发送数据的指针
 * @param TxLen [in] 需要发送的长度
 * @return  返回发送的长度， -1表示发送失败.
 */
static int32_t SSL_SocketTx(int32_t Socketfd, void *Buf, uint16_t TxLen)
{
    struct timeval tm;
    fd_set WriteSet;
	int32_t Result;
	Result = send(Socketfd, (uint8_t *)Buf, TxLen, 0);

	if (Result < 0)
	{
		DBG_ERROR("TCP %d %d", Result, socket_errno(Socketfd));
		return -1;
	}
    FD_ZERO(&WriteSet);
    FD_SET(Socketfd, &WriteSet);
    tm.tv_sec = 75;
    tm.tv_usec = 0;
    Result = select(Socketfd + 1, NULL, &WriteSet, NULL, &tm);
    if(Result > 0)
    {
		DBG_INFO("TCP TX OK! %dbyte", TxLen);
		return Result;
    }
    else
    {
        DBG_ERROR("TCP TX ERROR");
        return -1;
    }
}

/**
 * @brief 接收SSL封装好的数据，如果使用socket编程的，可以直接参考，如果使用AT指令编程的，那么需要自己来实现
 * @param Socketfd [in] socket id，如果是AT指令，单路链接，传入0，不用管，多路链接的，传入CIPSTART时用的通道号
 * @param Buf [in] 存放接收数据的指针
 * @param TxLen [in] 需要接收的长度，可能会超出本次接收的长度，没关系
 * @return  返回接收的长度， -1表示接收失败.
 */
static int32_t SSL_SocketRx(int32_t Socketfd, void *Buf, uint16_t RxLen)
{
    struct timeval tm;
    fd_set ReadSet;
	int32_t Result;
    FD_ZERO(&ReadSet);
    FD_SET(Socketfd, &ReadSet);
    tm.tv_sec = 75;
    tm.tv_usec = 0;
    Result = select(Socketfd + 1, &ReadSet, NULL, NULL, &tm);
    if(Result > 0)
    {
    	Result = recv(Socketfd, Buf, RxLen, 0);
        if(Result == 0)
        {
        	DBG_ERROR("socket close!");
            return -1;
        }
        else if(Result < 0)
        {
        	DBG_ERROR("recv error %d", socket_errno(Socketfd));
            return -1;
        }
		return Result;
    }
    else
    {
    	return -1;
    }
}

static void SSL_Task(PVOID pParameter)
{
	USER_MESSAGE*    msg;
	uint8_t *RxData;
	uint8_t ReConnCnt, Error, Quit;
	int32_t Ret,RxLen = 0;
	int32_t Socketfd = -1;
	int32_t TopicSN, Result;
	SSL_CTX * SSLCtrl = SSL_CreateCtrl(0);
	SSL * SSLLink = NULL;
	T_AMOPENAT_SYSTEM_DATETIME Datetime;
	ReConnCnt = 0;
	if (!SSLCtrl)
	{
		DBG_ERROR("!");
		Quit = 1;
	}
	else
	{
		Quit = 0;
	}
	//需要对时间校准，DEMO中简化为直接设置时间了
	Datetime.nYear = 2017;
	Datetime.nMonth = 10;
	Datetime.nDay = 15;
	Datetime.nHour = 11;
	Datetime.nMin = 14;
	Datetime.nSec = 11;
	iot_os_set_system_datetime(&Datetime);
	//加载CA证书
	SSL_LoadKey(SSLCtrl, SSL_OBJ_X509_CACERT, DEMO_CA_CERT, strlen(DEMO_CA_CERT), NULL);
	while (!Quit)
	{
		SOCKET_CLOSE(Socketfd);
		if (SSLLink)
		{
			SSL_FreeLink(SSLLink);
			SSLLink = NULL;
		}
		iot_os_sleep(5000);	//这里最好使用timer来延迟，demo简化使用
		iot_os_stop_timer(hTimer);
		iot_os_start_timer(hTimer, 90*1000);//90秒内如果没有激活APN，重启模块
		ToFlag = 0;
		while (NWState != OPENAT_NETWORK_LINKED)
		{
			iot_os_wait_message(hSocketTask, (PVOID)&msg);
	        switch(msg->Type)
	        {
			case USER_MSG_TIMER:
				DBG_ERROR("network wait too long!");
				iot_os_sleep(500);
				iot_os_restart();
				break;
			default:
				break;
	        }
	        iot_os_free(msg);
		}
		iot_os_stop_timer(hTimer);
		DBG_INFO("start connect server");
		Socketfd = Socket_ConnectServer();
		if (Socketfd > 0)
		{
			ReConnCnt = 0;
		}
		else
		{
			ReConnCnt++;
			DBG_ERROR("retry %dtimes", ReConnCnt);
			if (ReConnCnt > SSL_RECONNECT_MAX)
			{
				iot_os_restart();
				while (1)
				{
					iot_os_sleep(5000);
				}
			}
			continue;
		}

		DBG_INFO("start ssl handshake");
		SSLLink = SSL_NewLink(SSLCtrl, Socketfd, NULL, 0, NULL, NULL);
		if (!SSLLink)
		{
			DBG_ERROR("!");
			Quit = 1;
			continue;
		}
		Ret = SSL_HandshakeStatus(SSLLink);
		if (Ret)
		{
			DBG_ERROR("ssl handshake fail %d", Ret);
		}
		else
		{
			DBG_INFO("ssl handshake ok");
		}
		iot_os_start_timer(hTimer, SSL_HEAT_TO*1000);//启动心跳计时
		ToFlag = 0;
		Error = 0;
		while(!Error && !Quit)
		{
			RxLen = 0;
			if (RxLen > 0)
			{
				continue;
			}
			else if (RxLen < 0)
			{
				Error = 1;
				continue;
			}
			else
			{
				while (ToFlag)
				{
					iot_os_wait_message(hSocketTask, (PVOID)&msg);
					switch(msg->Type)
					{
					case USER_MSG_TIMER:
						ToFlag = 0;
						if (Result < 0)
						{
							Error = 1;
						}
						else
						{
							iot_os_start_timer(hTimer, SSL_HEAT_TO*1000);//启动心跳计时
							//心跳时间到，发送一次请求，接收响应并打印
							Ret = SSL_Write(SSLLink, TEST_DATA, strlen(TEST_DATA));
							if (Ret < 0)
							{
								DBG_ERROR("ssl send error %d", Ret);
								Error = 1;
							}
							else
							{
								Ret = SSL_Read(SSLLink, &RxData);
								if (Ret <= 0)
								{
									DBG_ERROR("ssl receive error %d", Ret);
									Error = 1;
								}
								else
								{
									RxData[Ret] = 0;
									DBG_INFO("%s\r\n", RxData);
								}
							}
						}
						break;
					default:
						if (NWState != OPENAT_NETWORK_LINKED)
						{
							Error = 1;
						}
						break;
					}
					iot_os_free(msg);
				}
			}
		}
	}
	iot_os_stop_timer(hTimer);
	SOCKET_CLOSE(Socketfd);
	if (SSLLink)
	{
		SSL_FreeLink(SSLLink);
		SSLLink = NULL;
	}
	SSL_FreeCtrl(SSLCtrl);
	while (1)
	{
		iot_os_sleep(43200 * 1000);
	}
}

static void SSL_NetworkIndCallBack(E_OPENAT_NETWORK_STATE state)
{
	USER_MESSAGE * Msg = iot_os_malloc(sizeof(USER_MESSAGE));
    T_OPENAT_NETWORK_CONNECT networkparam;
    if (state == OPENAT_NETWORK_READY)
    {
    	memset(&networkparam, 0, sizeof(T_OPENAT_NETWORK_CONNECT));
    	memcpy(networkparam.apn, "CMNET", strlen("CMNET"));
    	iot_network_connect(&networkparam);
    }

    Msg->Type = USER_MSG_NETWORK;
    DBG_INFO("%d", state);
    if (NWState != state)
    {
    	DBG_INFO("network ind state %d -> %d", NWState, state);
    	NWState = state;
    }
    iot_os_send_message(hSocketTask, (PVOID)Msg);

}

static void SSL_TimerHandle(T_AMOPENAT_TIMER_PARAMETER *pParameter)
{
	USER_MESSAGE *Msg = iot_os_malloc(sizeof(USER_MESSAGE));
	ToFlag = 1;
	Msg->Type = USER_MSG_TIMER;
	iot_os_send_message(hSocketTask, (PVOID)Msg);
	iot_os_stop_timer(hTimer);

}

void app_main(void)
{
    iot_network_set_cb(SSL_NetworkIndCallBack);
	hSocketTask = iot_os_create_task(SSL_Task,
                        NULL,
                        4096,
                        5,
                        OPENAT_OS_CREATE_DEFAULT,
                        "demo_socket_SSL");
	NWState = OPENAT_NETWORK_DISCONNECT;
	hTimer = iot_os_create_timer(SSL_TimerHandle, NULL);
	SSL_RegSocketCallback(SSL_SocketTx, SSL_SocketRx);
}
