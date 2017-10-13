#include "ssllib.h"
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

