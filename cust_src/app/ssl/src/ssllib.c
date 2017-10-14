#include "ssllib.h"
#define DBG_INFO(X, Y...)	iot_debug_print("%s %d:"X, __FUNCTION__, __LINE__, ##Y)
#define DBG_ERROR(X, Y...)	iot_debug_print("%s %d:"X, __FUNCTION__, __LINE__, ##Y)
#define DBG(X, Y...)		iot_debug_print(X,##Y)
static SocketAPI gSocketRead;
static SocketAPI gSocketWrite;
int OS_SocketRead(int SocketFd, void *Buf, uint16_t Len)
{
	if (gSocketRead)
	{
		return gSocketRead(SocketFd, Buf, Len);
	}
	return -1;
}
int OS_SocketWrite(int SocketFd, void *Buf, uint16_t Len)
{
	if (gSocketWrite)
	{
		return gSocketWrite(SocketFd, Buf, Len);
	}
	return -1;
}

void SSL_RegSocketCallback(SocketAPI SendFun, SocketAPI ReceiveFun)
{
	gSocketWrite = SendFun;
	gSocketRead = ReceiveFun;
}
