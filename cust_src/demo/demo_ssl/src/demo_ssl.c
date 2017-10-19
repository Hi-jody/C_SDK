/*
 * ͨ������101.132.154.251 ����˫����֤��SSL���ֹ��̣������ݼ����շ����÷�������ʱ��رգ��Լ�����ʱ������ʹ���Լ��ķ�����
 */
#include "string.h"
#include "iot_os.h"
#include "iot_debug.h"
#include "iot_network.h"
#include "iot_socket.h"
#include "iot_fs.h"
#include "iot_flash.h"
#include "iot_types.h"
#include "iot_pmd.h"
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
#if 0
#define TEST_URL					"www.icbc.com.cn"
#define TEST_DATA					"GET / HTTP/1.1\r\nHost: www.icbc.com.cn\r\nConnection: keep-alive\r\n\r\n"
#define TEST_PORT					(443)
#else
#define TEST_IP						"101.132.154.251"
#define TEST_DATA					"GET / HTTP/1.1\r\nHost: 101.132.154.251\r\nConnection: keep-alive\r\n\r\n"
#define TEST_PORT					443
#endif

#define SSL_RECONNECT_MAX			(8)
#define SSL_HEAT_TO					20
static HANDLE hTimer;
static HANDLE hSocketTask;
static E_OPENAT_NETWORK_STATE NWState;				//����״̬
static uint8_t ToFlag = 0;

//��֤�飬�����ã����ʹ���Լ��ķ��������������޸�
const char *RootCert = "-----BEGIN CERTIFICATE-----\r\n"
		"MIIDwzCCAqugAwIBAgIBATANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJjaDEL\r\n"
		"MAkGA1UECBMCemoxCzAJBgNVBAcTAmp4MQ4wDAYDVQQKEwVhZG1pbjEOMAwGA1UE\r\n"
		"CxMFYWRtaW4xDTALBgNVBAMTBHJvb3QxEzARBgkqhkiG9w0BCQEWBG5vbmUwHhcN\r\n"
		"MTcxMDE4MDUxMTAwWhcNMjcxMDE4MDUxMTAwWjBrMQswCQYDVQQGEwJjaDELMAkG\r\n"
		"A1UECBMCemoxCzAJBgNVBAcTAmp4MQ4wDAYDVQQKEwVhZG1pbjEOMAwGA1UECxMF\r\n"
		"YWRtaW4xDTALBgNVBAMTBHJvb3QxEzARBgkqhkiG9w0BCQEWBG5vbmUwggEiMA0G\r\n"
		"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDft3k9SSXXsteJ6W7XWXNDp63aJ7YG\r\n"
		"CLjV9cnhdntc29WvAzvL2jv8lQTgOJ9WLpnhtDawCx8Hm+uqpfHo1xst6QFTtW6t\r\n"
		"lG/KmtNYWc8YuDi1l4MX97U4ebm7ZUzNy6RY63qSvPmdXk3hhqKSFa4jL14H6doI\r\n"
		"juoUyRqm7knJldhjMY0dnW42uHCCAHFIX1r+hYoWhEXK4wE4ft6cWYp1MIGncDTS\r\n"
		"OQL6odJKeIv5p40PkmfkMAM20zWSmp3YfZVxuLEjBd652sou/yWbCx5LbnQspY/m\r\n"
		"wVnTTZNdxmvRC6TPg/E+Bo3qhpD/SqK2Ae6ppWBJwj19k55+2mFuTAJvAgMBAAGj\r\n"
		"cjBwMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFC5rENj+9wbLuQMM4jbkiaF+\r\n"
		"jleZMAsGA1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgEN\r\n"
		"BBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsFAAOCAQEAjmp5xahyFueo\r\n"
		"UrqnvPhwWfiQgitTyI8qM7xAawlMeXrpaD5w2PPk8maKHJ9aEVUL+qXYxnoeUq4L\r\n"
		"/hvmIWwB4SWoeMVaLBMLGlDhW+tQJoo36+gqTZXtDiGH178UzunjIbODyEl1Q3Ni\r\n"
		"7BefeRKjmz11HzVi1T4vv7F25pJY02PpDWVJSNGPDNwKE+YgODbntSGEX3NgLqaN\r\n"
		"8cxQivf9hFPQYihs+b0qt+5J15oJIiI877JlfoNTUtoLakPyt9wnvZgTHhH8M/bd\r\n"
		"44TNS8Aha2L7WhmBmaOfIQrjScjOnUlfahR/vPEw3BBvnCs1w87oMb+iGCU2AVJn\r\n"
		"sL+R9Q/sTA==\r\n"
		"-----END CERTIFICATE-----";

const char *ClientCert = "-----BEGIN CERTIFICATE-----\r\n"
		"MIIDPjCCAiagAwIBAgIBBjANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJjaDEL\r\n"
		"MAkGA1UECBMCemoxCzAJBgNVBAcTAmp4MQ4wDAYDVQQKEwVhZG1pbjEOMAwGA1UE\r\n"
		"CxMFYWRtaW4xDTALBgNVBAMTBHJvb3QxEzARBgkqhkiG9w0BCQEWBG5vbmUwHhcN\r\n"
		"MTcxMDE5MDYyODAwWhcNMTgxMDE5MDYyODAwWjBtMQswCQYDVQQGEwJjaDELMAkG\r\n"
		"A1UECBMCemoxCzAJBgNVBAcTAmp4MQ0wCwYDVQQKEwRsdWF0MQ0wCwYDVQQLEwRs\r\n"
		"dWF0MREwDwYDVQQDDAhzc2xfdGVzdDETMBEGCSqGSIb3DQEJARYEbm9uZTCBnzAN\r\n"
		"BgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx6y1x3XuGa9B0KI9KZRMvjAkUKRV/HXM\r\n"
		"f2MhI6Q5EqyQIJbZBdfu7Tenobgggdncy0TT/eXZW8oTTM8cB+S4rGj4h98Osk7C\r\n"
		"XhYx/7Vd883jicfH+VJks1nvCNZI8bifSCJFHHtY4tNME8MbLxUu3DzRBYXzq2ZS\r\n"
		"e37aenI97EcCAwEAAaNvMG0wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOn+eScMY\r\n"
		"BS2S8E1OYL/O/4+11ZAwCwYDVR0PBAQDAgSwMBEGCWCGSAGG+EIBAQQEAwIFoDAe\r\n"
		"BglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4IB\r\n"
		"AQAlMHCy9FGRaF25TaHhEftbTe8iydq4/4xJUSLP3QcbDZxYDzYeBs9IgIv6BX24\r\n"
		"KIuxSwgwWNhTqEeapgI+pnImQCLGEjNq8Wn/JYXCrclqkMmQr1CHJiCEZtYBN/ou\r\n"
		"ky4wgEfTKUMqlRInZFrsQs9HFjINqXwz9Gg2PQeshPHVESolBBHohl831yuqMyQA\r\n"
		"YE0weAXFfp0VEdetVSetyVqCO6lb5XQZlozsKw6h5SUDw+uTYxBZdnyItOmhZdt3\r\n"
		"swZgYd3Dbg8KAI0P/PETf4xnMVR2NicbYc+zOuA68EUxwTQi6JkHeLaFNtAnltr8\r\n"
		"dedN8rjgY/b0z2MTzVY3OGLx\r\n"
		"-----END CERTIFICATE-----";

const char *ClientRSAKey = "-----BEGIN RSA PRIVATE KEY-----\r\n"
		"MIICXgIBAAKBgQDHrLXHde4Zr0HQoj0plEy+MCRQpFX8dcx/YyEjpDkSrJAgltkF\r\n"
		"1+7tN6ehuCCB2dzLRNP95dlbyhNMzxwH5LisaPiH3w6yTsJeFjH/tV3zzeOJx8f5\r\n"
		"UmSzWe8I1kjxuJ9IIkUce1ji00wTwxsvFS7cPNEFhfOrZlJ7ftp6cj3sRwIDAQAB\r\n"
		"AoGBAMRVFggh9RRcNyKl4+3WW/9F5u9EJygty/4VwqgA+f1an/zrVklgoRWu+60Q\r\n"
		"FyaWyXs1Gh00vBx8/a0wmCdKxilED3abjT6jbzoAKJYsjcRqthNAFlb6bNHdyQPO\r\n"
		"HZvuKsBS6ZHCeSoNYFuW4ncGCfEsvV/qRzYkAbr5CqVPxriBAkEA4n/lBp2ylgfb\r\n"
		"xK8WbGOXO+fPPAj8X7Ap+iTIjnespn0sIaMS1xMyQ5hXhJu7+BGsLDg6X8tWIWWt\r\n"
		"c7khvydkTwJBAOGuZlpxuJ+pU1Dlsd6W8fki3B1Mi+4U8dRiiq86lehw7vo0oI5U\r\n"
		"1NySbKqQDERL+SbRYL73a3CgBllq5TpNYokCQQC7BIE1ukY4DRsQRsWMD5tTEm+R\r\n"
		"kZXY6JtweKjEwdnjyl0DFSQ8RBRvrb0tuG03QlhYVsEUUc+3Wb4jXEyaCkuPAkAU\r\n"
		"aBatOvc8yKzV9c8dl3yN0I8ivxcwEgjD8Z0ktyFzATM6wKN7+0O8JilZSukxC8Wd\r\n"
		"svUSj4DRkEbCsx3DJdgxAkEAuBZ0Dmv3XYJ3zn/MAsNZzWLbbN+YPZ11nUTNE9FU\r\n"
		"M3paJdqmD70wz3tn5QhcIXbJ/90qs4iPNZ52qiOYnaMD3Q==\r\n"
		"-----END RSA PRIVATE KEY-----";
#ifdef TEST_URL
static uint32_t SSL_Gethostbyname(void)
{
    //��������
	ip_addr_t *IP;
    struct hostent *hostentP = NULL;
    char *ipAddr = NULL;

    //��ȡ����ip��Ϣ
    hostentP = gethostbyname(TEST_URL);

    if (!hostentP)
    {
        DBG_ERROR("gethostbyname %s fail", TEST_URL);
        return 0;
    }

    // ��ipת�����ַ���
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
	    // ����TCP����
	    memset(&TCPServerAddr, 0, sizeof(TCPServerAddr)); // ��ʼ����������ַ
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
 * @brief ����SSL��װ�õ����ݣ����ʹ��socket��̵ģ�����ֱ�Ӳο������ʹ��ATָ���̵ģ���ô��Ҫ�Լ���ʵ��
 * @param Socketfd [in] socket id�������ATָ���·���ӣ�����0�����ùܣ���·���ӵģ�����CIPSTARTʱ�õ�ͨ����
 * @param Buf [in] ��Ҫ�������ݵ�ָ��
 * @param TxLen [in] ��Ҫ���͵ĳ���
 * @return  ���ط��͵ĳ��ȣ� -1��ʾ����ʧ��.
 */
static int32_t SSL_SocketTx(int32_t Socketfd, void *Buf, uint16_t TxLen)
{
    struct timeval tm;
    fd_set WriteSet;
	int32_t Result;
	DBG_INFO("%dbyte need send", TxLen);
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
 * @brief ����SSL��װ�õ����ݣ����ʹ��socket��̵ģ�����ֱ�Ӳο������ʹ��ATָ���̵ģ���ô��Ҫ�Լ���ʵ��
 * @param Socketfd [in] socket id�������ATָ���·���ӣ�����0�����ùܣ���·���ӵģ�����CIPSTARTʱ�õ�ͨ����
 * @param Buf [in] ��Ž������ݵ�ָ��
 * @param TxLen [in] ��Ҫ���յĳ��ȣ����ܻᳬ�����ν��յĳ��ȣ�û��ϵ
 * @return  ���ؽ��յĳ��ȣ� -1��ʾ����ʧ��.
 */
static int32_t SSL_SocketRx(int32_t Socketfd, void *Buf, uint16_t RxLen)
{
    struct timeval tm;
    fd_set ReadSet;
	int32_t Result;
    FD_ZERO(&ReadSet);
    FD_SET(Socketfd, &ReadSet);
    tm.tv_sec = 30;
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
        DBG_INFO("recv %d\r\n", Result);
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
	int32_t Ret;
	int32_t Socketfd = -1;
	SSL_CTX * SSLCtrl = SSL_CreateCtrl(1); //����1��session����������Ĵ�ӡ��KEY��ʧ��
	SSL * SSLLink = NULL;
	T_AMOPENAT_SYSTEM_DATETIME Datetime;
	int i;
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


	Ret = SSL_LoadKey(SSLCtrl, SSL_OBJ_X509_CACERT, RootCert, strlen(RootCert), NULL);
	//�����˫����֤�ģ���Ҫ���ؿͻ��˵�֤���˽Կ
	Ret = SSL_LoadKey(SSLCtrl, SSL_OBJ_X509_CERT, ClientCert, strlen(ClientCert), NULL);
	Ret = SSL_LoadKey(SSLCtrl, SSL_OBJ_RSA_KEY, ClientRSAKey, strlen(ClientRSAKey), NULL);

	while (!Quit)
	{
		SOCKET_CLOSE(Socketfd);
		if (SSLLink)
		{
			SSL_FreeLink(SSLLink);
			SSLLink = NULL;
		}
		iot_os_sleep(5000);	//�������ʹ��timer���ӳ٣�demo��ʹ��
		iot_os_stop_timer(hTimer);
		iot_os_start_timer(hTimer, 90*1000);//90�������û�м���APN������ģ��
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
		//��Ҫ��ʱ��У׼��DEMO�м�Ϊֱ������ʱ����
		Datetime.nYear = 2017;
		Datetime.nMonth = 10;
		Datetime.nDay = 19;
		Datetime.nHour = 11;
		Datetime.nMin = 14;
		Datetime.nSec = 11;
		iot_os_set_system_datetime(&Datetime);

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
			Quit = 1;
			continue;
		}
		else
		{
			DBG_INFO("ssl handshake OK");

		}

		iot_os_start_timer(hTimer, 1*1000);//1�����һ��HTTP����
		ToFlag = 0;
		Error = 0;
		while(!Error && !Quit)
		{

			while (ToFlag)
			{
				iot_os_wait_message(hSocketTask, (PVOID)&msg);
				switch(msg->Type)
				{
				case USER_MSG_TIMER:
					ToFlag = 0;
					DBG_INFO("HTTP GET");
					Ret = SSL_Write(SSLLink, TEST_DATA, strlen(TEST_DATA));
					if (Ret < 0)
					{
						DBG_ERROR("ssl send error %d", Ret);
						Error = 1;
					}
					else
					{
						Ret = 0;
						while (!Ret)
						{
							Ret = SSL_Read(SSLLink, &RxData);
						}

						if (Ret < 0)
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
					Quit = 1;
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
	iot_pmd_exit_deepsleep();
}
