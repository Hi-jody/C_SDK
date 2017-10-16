/*
 * 1��DEMO����MQTT-3.1.1Э���д�������ÿͻ���MQTT.fx-1.3.0������ʾ�˱�������1~14��ʹ�÷�����
 *   ���������˻Ự�����ܣ����Ҳ��ʹ����Ϣ���Թ���
 * 2��DEMO����2�����⣬air202/gprs/tx,air202/ctrl��Ϊ��ֹ��ͻ�����û��޸�Ϊ��������
 * 3���û��Ŀͻ����϶���1�����⣬air202/gprs/rx��Ϊ��ֹ��ͻ�����û��޸�Ϊ�������⣬����ʹ���Լ��ķ�����
 * 4��connect�ɹ���ģ����air202/gprs/tx������publishһ����¼��Ϣ
 * 5���û���air202/gprs/tx������publish���ݣ�ģ����պ�ԭ��publish��air202/gprs/rx
 * 6���û���air202/ctrl������publish"quit"��ģ����air202/gprs/tx������publishһ���˳���Ϣ��
 * 	    ģ��ȡ�����ж��ģ�disconnect������ֹͣ
 * 7��DEMO���б��ĳ���������1460�������޸�
 * ��������������������������������������������������������������������������������
 * 8��DEMO�������������ճ����QOS����ֻ������򵥵�˳�����
 *   �ڲ���ʱ�����û���޸�DEMO��DEMO��������ʹ��QOS2����Ҫ��ʱ���ڣ�1S���ڿͻ����Ͽ��ٷ���������Ϣ��������QOS2����Ϣ
 *   ���ܻᵼ��DEMO��QOS�����߼���������յ�ճ��
 * 9�������ڿͻ��˽��յ�ģ�鷵�ص���Ϣ���Ϳͻ��˷�������һ�������ݣ����ٷ�����һ��
 * ��������������������������������������������������������������������������������
 * 10��MQTTЭ�����ھ�����ת�����Կͻ����յ�ģ��ķ�����Ϣ�������1~3�����Ҷ�������
 * 11���궨���ȫ�ֱ����ɸ���ʵ������޸�
 */
#include "string.h"
#include "iot_os.h"
#include "iot_debug.h"
#include "iot_network.h"
#include "iot_socket.h"
#include "mqttlib.h"

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


#define MQTT_RECONNECT_MAX			(8)				//�����������
#define MQTT_PUBLISH_DEFAULT_QOS	MQTT_MSG_QOS1	//ģ��PUBLISH��Ĭ��QOS,QOS1
#define MQTT_PAYLOAD_MAX			(1400)			//��Ч�غ���󳤶�1400
#define MQTT_MSG_LEN_MAX			(1460)			//MQTT������󳤶�1460
#define MQTT_HEAD_LEN_MAX			(128)			//MQTT��ͷ��󳤶�128
#define MQTT_TCP_TO					(60)			//MQTT TCP�շ���ʱ60S
#define MQTT_HEAT_TO				(120)			//MQTT��������120S

#ifdef __SSL_ENABLE__
#define MQTT_SSL_URL				"mqtt.test.com"
#define MQTT_SSL_PORT				(18883)
#else
#define MQTT_URL					"lbsmqtt.airm2m.com"
#define MQTT_PORT					(1884)
#endif
/*************************************************************/
const MQTT_SubscribeStruct DemoSub[2] =
{
		{
				.Char = "air202/gprs/tx",
				.Qos = MQTT_SUBSCRIBE_QOS2,
		},
		{
				.Char = "air202/ctrl",
				.Qos = MQTT_SUBSCRIBE_QOS2,
		}
};
const int8_t *DemoPublishTopicGPRS = "air202/gprs/rx";//ģ�鷢����������������
const int8_t *DemoClientID = NULL;	//�����дNULL�����ɷ������Զ�����
//���±������ɸ���ʵ����Ҫ��дNULL�����Ǳ���ͬʱ�޸�CONNECT�е����ӱ�ʶλ����������
const int8_t *DemoWillTopic = "air202/gprs/rx";
const int8_t *DemoWillMsg = "error offline";
const int8_t *DemoUser = "user";
const int8_t *DemoPasswd = "password";
/*************************************************************/
static HANDLE hTimer;
static HANDLE hSocketTask;
static E_OPENAT_NETWORK_STATE NWState;				//����״̬
static uint8_t MQTTRxBuf[MQTT_MSG_LEN_MAX];			//MQTT���ձ��Ļ���
static uint8_t MQTTTxBuf[MQTT_MSG_LEN_MAX];			//MQTT���ͱ��Ļ���
static uint8_t MQTTTempBuf[MQTT_PAYLOAD_MAX];		//MQTT��ʱ���ݻ���
static uint8_t MQTTPayload[MQTT_PAYLOAD_MAX];		//MQTT��Ч�غɻ���
static Buffer_Struct TxBuffer;
static Buffer_Struct PayloadBuffer;
static uint16_t gPackID = 0;						//ȫ�ֱ��ı�ʶ��
static uint8_t ToFlag = 0;
static uint32_t MQTT_Gethostbyname(void)
{
    //��������
	ip_addr_t *IP;
    struct hostent *hostentP = NULL;
    char *ipAddr = NULL;

    //��ȡ����ip��Ϣ
    hostentP = gethostbyname(MQTT_URL);

    if (!hostentP)
    {
        DBG_ERROR("gethostbyname %s fail", MQTT_URL);
        return 0;
    }

    // ��ipת�����ַ���
    ipAddr = ipaddr_ntoa((const ip_addr_t *)hostentP->h_addr_list[0]);

    DBG_ERROR("gethostbyname %s ip %s", MQTT_URL, ipAddr);
    IP = (ip_addr_t *)hostentP->h_addr_list[0];
    return IP->addr;
}

static int32_t Socket_ConnectServer(void)
{
	uint32_t IP;
    int connErr;
    struct sockaddr_in TCPServerAddr;
	int32_t Socketfd;
	IP = MQTT_Gethostbyname();
	if (IP)
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
	    TCPServerAddr.sin_port = htons((unsigned short)MQTT_PORT);
	    TCPServerAddr.sin_addr.s_addr = IP;
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

static int32_t MQTT_TCPTx(int32_t Socketfd, uint16_t TxLen, uint32_t TimeoutSec)
{
    struct timeval tm;
    fd_set WriteSet;
	int32_t Result;
	Result = send(Socketfd, MQTTTxBuf, TxLen, 0);

	if (Result < 0)
	{
		DBG_ERROR("TCP %d %d", Result, socket_errno(Socketfd));
		return Result;
	}
    FD_ZERO(&WriteSet);
    FD_SET(Socketfd, &WriteSet);
    tm.tv_sec = TimeoutSec;
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

static int32_t MQTT_TCPRx(int32_t Socketfd, uint32_t TimeoutSec)
{
    struct timeval tm;
    fd_set ReadSet;
	int32_t Result;
    FD_ZERO(&ReadSet);
    FD_SET(Socketfd, &ReadSet);
    tm.tv_sec = TimeoutSec;
    tm.tv_usec = 0;
    Result = select(Socketfd + 1, &ReadSet, NULL, NULL, &tm);
    if(Result > 0)
    {
    	Result = recv(Socketfd, MQTTRxBuf, sizeof(MQTTRxBuf), 0);
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
    return Result;
}

//MQTT����Ԥ�ȴ���
static int32_t MQTT_RxPreDeal(MQTT_HeadStruct *Rxhead, int32_t RxLen)
{
	uint8_t *Payload = NULL;
	uint32_t PayloadLen;
	uint32_t DealLen;
	Rxhead->Data = MQTTTempBuf;
	Payload = MQTT_DecodeMsg(Rxhead, MQTT_HEAD_LEN_MAX, &PayloadLen, MQTTRxBuf, RxLen, &DealLen);
	if ((uint32_t)Payload != INVALID_HANDLE_VALUE)
	{
		if (DealLen != RxLen)
		{
			DBG_INFO("more data need deal,but demo do not deal! %u %u", DealLen, RxLen);
		}
		Rxhead->Data[Rxhead->DataLen] = 0;
		if (Payload && PayloadLen)
		{
			memcpy(PayloadBuffer.Data, Payload, PayloadLen);
			PayloadBuffer.Pos = PayloadLen;
		}
	}
	else
	{
		DBG_ERROR("MQTT MSG ERROR!");
		return -1;
	}
	return 0;
}

//MQTT CONNECT����
static int32_t MQTT_Connect(int32_t Socketfd)
{
	uint32_t TxLen;
	int32_t RxLen;
	MQTT_HeadStruct Rxhead;

	TxBuffer.Pos = 0;
	PayloadBuffer.Pos = 0;
	TxLen = MQTT_ConnectMsg(&TxBuffer, &PayloadBuffer,
			MQTT_CONNECT_FLAG_CLEAN|MQTT_CONNECT_FLAG_WILL|MQTT_CONNECT_FLAG_WILLQOS1|MQTT_CONNECT_FLAG_USER|MQTT_CONNECT_FLAG_PASSWD,
			MQTT_HEAT_TO * 2, DemoClientID, DemoWillTopic, DemoUser, DemoPasswd, (uint8_t *)DemoWillMsg, strlen(DemoWillMsg));
	if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
	{
		return -1;
	}
	RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
	if (RxLen <= 0)
	{
		return -1;
	}
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}

	if (Rxhead.Cmd != MQTT_CMD_CONNACK)
	{
		DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
		return -1;
	}
	if (Rxhead.Data[1])
	{
		DBG_ERROR("CONNACK FAIL %02x %02x", Rxhead.Data[0], Rxhead.Data[1]);
		return -1;
	}
	return 0;
}

//MQTT�����������
static int32_t MQTT_Subscribe(int32_t Socketfd)
{
	int i;
	uint32_t TxLen;
	int32_t RxLen;
	MQTT_HeadStruct Rxhead;
	TxBuffer.Pos = 0;
	PayloadBuffer.Pos = 0;
	gPackID++;
	TxLen = MQTT_SubscribeMsg(&TxBuffer, &PayloadBuffer, gPackID, (MQTT_SubscribeStruct *)DemoSub, sizeof(DemoSub)/sizeof(MQTT_SubscribeStruct));
	if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
	{
		return -1;
	}
	RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
	if (RxLen <= 0)
	{
		return -1;
	}
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}
	if (Rxhead.Cmd != MQTT_CMD_SUBACK)
	{
		DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
		return -1;
	}
	if (Rxhead.PackID != gPackID)
	{
		DBG_ERROR("gPackID ERROR %u %u", (uint32_t)Rxhead.PackID, (uint32_t)gPackID);
		return -1;
	}

	//�����˶��ٸ����⣬���ж��ٸ��ظ��ֽ�
	for (i = 0; i < sizeof(DemoSub)/sizeof(MQTT_SubscribeStruct);i++)
	{
		switch (PayloadBuffer.Data[i])
		{
		case 0:
		case 1:
		case 2:
			DBG_INFO("Subscribe %d ok %02x", i,PayloadBuffer.Data[0]);
			break;
		default:
			DBG_ERROR("Subscribe fail %02x", PayloadBuffer.Data[0]);
			return -1;
		}
	}
	return 1;
}

//MQTT ȡ�������������
static int32_t MQTT_Unsubscribe(int32_t Socketfd)
{
	uint32_t TxLen;
	int32_t RxLen;
	MQTT_HeadStruct Rxhead;
	TxBuffer.Pos = 0;
	PayloadBuffer.Pos = 0;
	gPackID++;
	TxLen = MQTT_UnSubscribeMsg(&TxBuffer, &PayloadBuffer, gPackID, (MQTT_SubscribeStruct *)DemoSub, sizeof(DemoSub)/sizeof(MQTT_SubscribeStruct));
	if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
	{
		return -1;
	}
	RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
	if (RxLen <= 0)
	{
		return -1;
	}
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}
	if (Rxhead.Cmd != MQTT_CMD_UNSUBACK)
	{
		DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
		return -1;
	}
	if (Rxhead.PackID != gPackID)
	{
		DBG_ERROR("gPackID ERROR %u %u", (uint32_t)Rxhead.PackID, (uint32_t)gPackID);
		return -1;
	}
	DBG_INFO("Unsubscribe ok");
	return 0;
}

//MQTT Publish��Ϣ������������, Qosֻ����0��MQTT_MSG_QOS1��MQTT_MSG_QOS2֮һ
//DEMOĬ��ʹ��CleanSession, ���IsDup������0
static int32_t MQTT_PublishToServer(int32_t Socketfd, uint8_t Qos, uint8_t IsDup, uint8_t IsRetain)
{
	uint32_t TxLen;
	int32_t RxLen;
	uint8_t Flag;
	MQTT_HeadStruct Rxhead;

	switch (Qos)
	{
	case 0:
		break;
	case MQTT_MSG_QOS1:
		break;
	case MQTT_MSG_QOS2:
		break;
	default:
		return -1;
	}
	Flag = Qos;
	if (Qos)
	{
		gPackID++;
		if (IsRetain)
		{
			Qos |= MQTT_MSG_RETAIN;
		}
		if (IsDup)
		{
			Qos |= MQTT_MSG_DUP;
		}
	}
	else
	{
		if (IsRetain)
		{
			Qos |= MQTT_MSG_RETAIN;
		}
	}
	TxBuffer.Pos = 0;
	TxLen = MQTT_PublishMsg(&TxBuffer, Flag, gPackID, DemoPublishTopicGPRS, PayloadBuffer.Data, PayloadBuffer.Pos);
	if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
	{
		return -1;
	}
	//QOS0
	if (!Qos)
	{
		DBG_INFO("PUBLISH QOS0 OK!");
		return 0;
	}

	RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
	if (RxLen <= 0)
	{
		return -1;
	}
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}
	//QOS1
	if (Qos == MQTT_MSG_QOS1)
	{
		if (Rxhead.Cmd != MQTT_CMD_PUBACK)
		{
			DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
			return -1;
		}
		if (Rxhead.PackID != gPackID)
		{
			DBG_ERROR("gPackID ERROR %u %u", (uint32_t)Rxhead.PackID, (uint32_t)gPackID);
			return -1;
		}
		DBG_INFO("PUBLISH QOS1 OK!");
		return 0;
	}
	else
	{
		//QOS2�ĵ�1�׶�
		if (Rxhead.Cmd != MQTT_CMD_PUBREC)
		{
			DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
			return -1;
		}
		if (Rxhead.PackID != gPackID)
		{
			DBG_ERROR("gPackID ERROR %u %u", (uint32_t)Rxhead.PackID, (uint32_t)gPackID);
			return -1;
		}
	}
	//QOS2�ĵ�2~3�׶�
	TxBuffer.Pos = 0;
	TxLen = MQTT_PublishCtrlMsg(&TxBuffer, MQTT_CMD_PUBREL, gPackID);
	if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
	{
		return -1;
	}

	RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
	if (RxLen <= 0)
	{
		return -1;
	}
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}

	if (Rxhead.Cmd != MQTT_CMD_PUBCOMP)
	{
		DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
		return -1;
	}
	if (Rxhead.PackID != gPackID)
	{
		DBG_ERROR("gPackID ERROR %u %u", (uint32_t)Rxhead.PackID, (uint32_t)gPackID);
		return -1;
	}
	DBG_INFO("PUBLISH QOS2 OK!");
	return 0;
}

//MQTT ������Publish��Ϣ��ģ����̣�����������һ��������ţ�0 "air202/gprs/tx" 1 "air202/ctrl"
static int32_t MQTT_PublishFromServer(int32_t Socketfd, int32_t RxLen)
{
	int32_t IsFormCtrlTopic;
	uint32_t TxLen;
	MQTT_HeadStruct Rxhead;
	uint16_t PackID;

	TxBuffer.Pos = 0;
	PayloadBuffer.Pos = 0;
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}
	if (Rxhead.Cmd != MQTT_CMD_PUBLISH)
	{
		DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
		return -1;
	}
	if (!strcmp(Rxhead.Data, DemoSub[0].Char))
	{
		IsFormCtrlTopic = 0;
	}
	else if (!strcmp(Rxhead.Data, DemoSub[1].Char))
	{
		IsFormCtrlTopic = 1;
	}
	else
	{
		DBG_ERROR("unknow topic %s", Rxhead.Data);
		return -1;
	}

	PackID = Rxhead.PackID;
	switch (Rxhead.Flag & MQTT_MSG_QOS_MASK)
	{
	case 0:
		DBG_INFO("RX PUBLISH QOS0 OK! %d", IsFormCtrlTopic);
		return IsFormCtrlTopic;

	case MQTT_MSG_QOS1:
		TxBuffer.Pos = 0;
		TxLen = MQTT_PublishCtrlMsg(&TxBuffer, MQTT_CMD_PUBACK, PackID);
		if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
		{
			return -1;
		}
		DBG_INFO("RX PUBLISH QOS1 OK! %d", IsFormCtrlTopic);
		return IsFormCtrlTopic;

	case MQTT_MSG_QOS2:
		TxBuffer.Pos = 0;
		TxLen = MQTT_PublishCtrlMsg(&TxBuffer, MQTT_CMD_PUBREC, PackID);
		if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
		{
			return -1;
		}

		RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
		if (RxLen <= 0)
		{
			return -1;
		}
		if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
		{
			return -1;
		}
		if (Rxhead.Cmd != MQTT_CMD_PUBREL)
		{
			DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
			return -1;
		}
		if (Rxhead.PackID != PackID)
		{
			DBG_ERROR("PackID ERROR %u %u", (uint32_t)Rxhead.PackID, (uint32_t)PackID);
			return -1;
		}

		TxBuffer.Pos = 0;
		TxLen = MQTT_PublishCtrlMsg(&TxBuffer, MQTT_CMD_PUBCOMP, PackID);
		if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
		{
			return -1;
		}
		DBG_INFO("RX PUBLISH QOS2 OK! %d", IsFormCtrlTopic);
		return IsFormCtrlTopic;
		break;
	default:
		DBG_ERROR("unknow qos %02x", Rxhead.Flag);
		return -1;
	}
}

//MQTT ��������
static int32_t MQTT_Heart(int32_t Socketfd)
{
	uint32_t TxLen;
	int32_t RxLen;
	MQTT_HeadStruct Rxhead;
	TxBuffer.Pos = 0;
	TxLen = MQTT_SingleMsg(&TxBuffer, MQTT_CMD_PINGREQ);
	if (MQTT_TCPTx(Socketfd, TxLen, MQTT_TCP_TO) < 0)
	{
		return -1;
	}
	RxLen = MQTT_TCPRx(Socketfd, MQTT_TCP_TO);
	if (RxLen <= 0)
	{
		return -1;
	}
	if (MQTT_RxPreDeal(&Rxhead, RxLen) < 0)
	{
		return -1;
	}
	if (Rxhead.Cmd != MQTT_CMD_PINGRESP)
	{
		DBG_ERROR("UNEXPECT CMD %02x", Rxhead.Cmd);
		return -1;
	}
	DBG_INFO("HEART OK!");
	return 0;
}

static void MQTT_Task(PVOID pParameter)
{
	USER_MESSAGE*    msg;
	uint8_t ReConnCnt, Error, Quit;
	int32_t RxLen = 0;
	int32_t Socketfd = -1;
	int32_t TopicSN, Result;
	TxBuffer.Data = MQTTTxBuf;
	TxBuffer.MaxLen = sizeof(MQTTTxBuf);
	TxBuffer.Pos = 0;
	PayloadBuffer.Data = MQTTPayload;
	PayloadBuffer.MaxLen = sizeof(MQTTPayload);
	PayloadBuffer.Pos = 0;
	ReConnCnt = 0;

	Quit = 0;
	while (!Quit)
	{
		SOCKET_CLOSE(Socketfd);
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
			if (ReConnCnt > MQTT_RECONNECT_MAX)
			{
				iot_os_restart();
				while (1)
				{
					iot_os_sleep(5000);
				}
			}
			continue;
		}

		DBG_INFO("MQTT CONNECT Start");
		if (MQTT_Connect(Socketfd) < 0)
		{
			DBG_INFO("MQTT CONNECT Fail");
			continue;
		}
		DBG_INFO("MQTT SUBSCRIBE Start");
		if (MQTT_Subscribe(Socketfd) < 0)
		{
			DBG_INFO("MQTT SUBSCRIBE Fail");
			continue;
		}

		DBG_INFO("MQTT PUBLISH hello Start");
		strcpy(PayloadBuffer.Data, "hello, this is air202 mqtt demo!");
		PayloadBuffer.Pos = strlen(PayloadBuffer.Data);
		if (MQTT_PublishToServer(Socketfd, MQTT_PUBLISH_DEFAULT_QOS, 0, 0) < 0)
		{
			DBG_INFO("MQTT PUBLISH hello Fail");
			continue;
		}

		iot_os_start_timer(hTimer, MQTT_HEAT_TO*1000);//����������ʱ
		ToFlag = 0;
		Error = 0;
		while(!Error && !Quit)
		{
			RxLen = 0;
			RxLen = MQTT_TCPRx(Socketfd, 1);
			if (RxLen > 0)
			{
				TopicSN = MQTT_PublishFromServer(Socketfd, RxLen);
				switch (TopicSN)
				{
				case 0:
					//����0����Ϣ��ԭ�ⲻ������������
					Result = MQTT_PublishToServer(Socketfd, MQTT_PUBLISH_DEFAULT_QOS, 0, 0);
					if (Result < 0)
					{
						Error = 1;
					}
					break;
				case 1:
					PayloadBuffer.Data[PayloadBuffer.Pos] = 0;
					DBG_INFO("%s",PayloadBuffer.Data);
					if (!strcmp(PayloadBuffer.Data, "quit"))
					{
						Quit = 1;
						DBG_INFO("MQTT QUIT Start");
						strcpy(PayloadBuffer.Data, "good bye!");
						PayloadBuffer.Pos = strlen(PayloadBuffer.Data);
						Result = MQTT_PublishToServer(Socketfd, MQTT_PUBLISH_DEFAULT_QOS, 0, 0);
						if (Result < 0)
						{
							Error = 1;
							break;
						}
						Result = MQTT_Unsubscribe(Socketfd);
						if (Result < 0)
						{
							DBG_ERROR("!");
							break;
						}
						TxBuffer.Pos = 0;
						Result = MQTT_SingleMsg(&TxBuffer, MQTT_CMD_DISCONNECT);
						MQTT_TCPTx(Socketfd, Result, MQTT_TCP_TO);
						iot_os_sleep(5000);
					}
					break;
				default:
					Error = 1;
					break;
				}
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
						Result = MQTT_Heart(Socketfd);
						if (Result < 0)
						{
							Error = 1;
						}
						else
						{
							iot_os_start_timer(hTimer, MQTT_HEAT_TO*1000);//����������ʱ
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
	DBG_INFO("MQTT QUIT!");
	iot_os_stop_timer(hTimer);
	SOCKET_CLOSE(Socketfd);
	while (1)
	{
		iot_os_sleep(43200 * 1000);
	}
}

static void MQTT_NetworkIndCallBack(E_OPENAT_NETWORK_STATE state)
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

static void MQTT_TimerHandle(T_AMOPENAT_TIMER_PARAMETER *pParameter)
{
	USER_MESSAGE *Msg = iot_os_malloc(sizeof(USER_MESSAGE));
	ToFlag = 1;
	Msg->Type = USER_MSG_TIMER;
	iot_os_send_message(hSocketTask, (PVOID)Msg);
	iot_os_stop_timer(hTimer);

}

VOID app_main(VOID)
{
    iot_network_set_cb(MQTT_NetworkIndCallBack);
	hSocketTask = iot_os_create_task(MQTT_Task,
                        NULL,
                        4096,
                        5,
                        OPENAT_OS_CREATE_DEFAULT,
                        "demo_socket_mqtt");
	NWState = OPENAT_NETWORK_DISCONNECT;
	hTimer = iot_os_create_timer(MQTT_TimerHandle, NULL);
}
