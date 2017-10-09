#ifndef __IOT_SOCKET_H__
#define __IOT_SOCKET_H__

#include "am_openat.h"

/**
 * @defgroup iot_sdk_socket socket�ӿ�
 * @{
 */
/**@example demo_socket/src/demo_socket.c
* socket�ӿ�ʾ��
*/
/**����socket
*@param		domain:		��֧��AF_INET (IPV4 ����Э��)
@param		type:		֧��SOCK_STREAM/SOCK_DGRAM���ֱ��ʾTCP��UDP����
@param		protocol:   ��֧��0


*@return	>=0: 	    socket�����������ں�������
*           <0:         ����socketʧ��
*@note      ������socket���ú���Ҫ��close����ر�
**/

int socket(int domain, int type, int protocol);
/**��ȡ������Ӧ��IP��ַ
*@param		name:		����������:www.airm2m.com/www.baidu.com
*@return	struct hostent �ṹ��: �ýṹ�������һ��DNS�����������ip��ַ
*           NULL:  ��������ʧ��
**/                       
struct hostent* gethostbyname(const char *name);
/**�ر�socket
*@param		fd:	����socket�ӿڷ��ص�socket������
*@return	0:  ��ʾ�ɹ�
            -1  ��ʾ�д���
*           
**/                          
int close (int fd);
/**����socket������
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      level: ֧��SOL_SOCKET/IPPROTO_TCP
@param      optname:  SOL_SOCKET��ӦoptnameΪ SO_DEBUG/SO_OOBINLINE/SO_SNDTIMEO/SO_RCVTIMEO
                      IPPROTO_TCP��ӦoptnameΪ SO_TCP_SACKDISABLE/SO_TCP_NODELAY
@param      optval_p:
@param      optlen:
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*
**/          

int setsockopt(int socketfd, 
                        int level, 
                        int optname,
                        void *optval_p, 
                        socklen_t optlen);
/**����socket�ı��ض˿ں�ip��ַ��һ����Է�����������Ҫ����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      my_addr:   ip��ַ�Ͷ˿ڣ�ipһ������INADDR_ANY
@param      addrlen:  ��ַ����
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*           
**/                         
int bind(int socketfd, 
                      const struct sockaddr *my_addr, 
                      socklen_t addrlen);
/**�����ͷ������˵�����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      addr:   ָ����������ַ�Ͷ˿�
@param      addrlen:  sizeof(struct sockaddr)
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*           
**/                                      
int connect(int socketfd, const struct sockaddr *addr, socklen_t addrlen);
/**����socket���ӣ�һ�����������������ͻ��˵�����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      backlog:   0
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*           
**/                             
int listen(int socketfd, 
                       int backlog);
/**�ȴ����ӣ�һ������listen֮��ȴ��ͻ��˵�����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      addr:   ���ؿͻ���ip��ַ�Ͷ˿�
@param      addrlen: ���ص�ַ����
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*@note      ������һֱ������֪���пͻ�������           
**/                             
int accept(int socketfd, 
                        struct sockaddr *addr, 
                        socklen_t *addrlen);
/**��������
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      buf:   ���ڴ�����ݵĻ���
@param      len:   buf�ĳ���
@param      flags: ��֧��MSG_DONTWAIT/MSG_PEEK/MSG_OOB������ͨ������ָ�������־��һ��Ϊ0

*@return	>0:  ���յ������ݳ���
            =0:  �Է��Ѿ��Ͽ�����
            <0:  ��ȡ����
*@note      ��flagsû������MSG_DONTWAIT���ú�����������ֱ�������ݻ��߶�ȡ��ʱ
**/                                        
int recv(int socketfd, 
                      void *buf, 
                      size_t len,
                      int flags);
/**����ָ��ip��ַ�����������ݣ�һ������UDP��ȡ����
*@param		sockfd:	����socket�ӿڷ��ص�socket������
@param      buf:   ���ڴ�����ݵĻ���
@param      len:   buf�ĳ���
@param      flags: ��֧��0
@param      src_addr: ip��ַ�Ͷ˿�
@param      addrlen: sizeof(struct sockaddr)

*@return	>0: ʵ���յ������ݳ���
            =0:  �Է��Ѿ��Ͽ�����
            <0:  ��ȡ����
**/   

int recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen);
/**��������
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      msg:   ��������
@param      len:   ���ݳ���
@param      flags: ��֧��MSG_DONTWAIT/MSG_OOB������ͨ������ָ�������־��һ��Ϊ0

*@return	>=0:  ʵ�ʷ��͵ĳ���
            <0: ���ʹ���
**/   

int send(int socketfd,
                      const void *msg,
                      size_t len,
                      int flags);
/**�������ݵ�ָ��ip��ַ��һ������udp��������
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      buf:   ��������
@param      len:   ���ݳ���
@param      flags: ��֧��0
@param      to_p: ָ��ip��ַ�Ͷ˿ں�
@param      tolen: sizeof(struct sockaddr)

*@return	>=0:  ʵ�ʷ��͵ĳ���
            <0:  ���ʹ���
**/                        
int sendto(int socketfd,
                        const void *buf,
                        size_t len,
                        int flags,
                        const struct sockaddr *to_p, 
                        socklen_t tolen);
/**������ʽ�ȴ�socket���ӵ�״̬
*@param		maxfdp1:	���socketfd+1
@param      readset:   ��ȡ���ϣ�����ΪNULL
@param      writeset:  д���ϣ�����ΪNULL
@param      exceptset: �쳣���ϣ�����ΪNULL
@param      timeout: ��ʱʱ��

*@return	0:   �ȴ���ʱ
            >0:  readset+writeset+exceptset�ļ��ϸ���
            <0  -1
**/                 
int select(int maxfdp1, 
                        fd_set *readset,
                        fd_set *writeset,
                        fd_set *exceptset,
                        struct timeval *timeout);
/**��ȡsocket�Ĵ���ֵ
*@param		socketfd:	����socket�ӿڷ��ص�socket������
*@return	[EBADF �� ENO_RECOVERY]
**/                                       
int socket_errno(int socketfd);
/**�����ֽ�˳��ת��Ϊ�����ֽ�˳��(16bits)
*@param		n: �����ֽ���������
*@return	�����ֽ�˳������
**/                 
#define htons(n) 				((n & 0xff) << 8) | ((n & 0xff00) >> 8)
/**�����ֽ�˳��ת��Ϊ�����ֽ�˳��(32bits)
*@param		n: �����ֽ���������
*@return	�����ֽ�˳������
**/           
#define htonl(n) 				((n & 0xff) << 24) |\
                                    ((n & 0xff00) << 8) |\
                                ((n & 0xff0000UL) >> 8) |\
                                    ((n & 0xff000000UL) >> 24)
/**�����ֽ�˳��ת��Ϊ�����ֽ�˳��(16bits)
*@param		n: �����ֽ�˳��
*@return	�����ֽ�˳��
**/                                           
#define ntohs(n) 				htons(n)
/**�����ֽ�˳��ת��Ϊ�����ֽ�˳��(32bits)
*@param		n: �����ֽ�˳��
*@return	�����ֽ�˳��
**/
#define ntohl(n) 				htonl(n)

/**��ip��ַ�ַ���תΪ��ֵ��ת�������ֵΪ�����ֽ�˳��
*@param		cp: ip��ַ�ַ���������"192.168.1.1"
*@param		addr: struct in_addr ���ص�ip��ַ��ֵ
*@return    1: �ɹ�
            0: ʧ��
**/ 
#define inet_aton(cp, addr)   ipaddr_aton(cp, (ip_addr_t*)addr)

/**��ip��ַ��ֵ(�����ֽ�˳��)��ת��Ϊip��ַ�ַ���
*@param		addr: struct in_addr ip��ַ��ֵ
*@return	ip��ַ�ַ���
**/ 
#define inet_ntoa(addr)       ipaddr_ntoa((ip_addr_t*)&(addr))


char *
ipaddr_ntoa(const ip_addr_t *addr);

int
ipaddr_aton(const char *cp, ip_addr_t *addr);

/** @}*/

#endif

