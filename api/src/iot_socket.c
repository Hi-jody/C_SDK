#include "iot_socket.h"

extern T_AMOPENAT_INTERFACE_VTBL * g_s_InterfaceVtbl;
#define IVTBL(func) (g_s_InterfaceVtbl->func)


/**����socket
*@param		domain:		��֧��AF_INET (IPV4 ����Э��)
@param		type:		֧��SOCK_STREAM/SOCK_DGRAM���ֱ��ʾTCP��UDP����
@param		protocol:   ��֧��0


*@return	>=0: 	    socket�����������ں�������
*           <0:         ����socketʧ��
*@note      ������socket���ú���Ҫ��close����ر�
**/

int socket(int domain, int type, int protocol)
{
    return IVTBL(socket)(domain, type, protocol);
}
/**��ȡ������Ӧ��IP��ַ
*@param		name:		����������:www.airm2m.com/www.baidu.com
*@return	struct hostent �ṹ��: �ýṹ�������һ��DNS�����������ip��ַ
*           NULL:  ��������ʧ��
**/                       
struct hostent* gethostbyname(const char *name)
{
    return IVTBL(gethostbyname)(name);
}
/**�ر�socket
*@param		fd:	����socket�ӿڷ��ص�socket������
*@return	0:  ��ʾ�ɹ�
            -1  ��ʾ�д���
*           
**/                          
int close (int fd)
{
    return IVTBL(close)(fd);
}
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
                        socklen_t optlen)
{
    return IVTBL(setsockopt)(socketfd, level, optname, optval_p, optlen);
}                 

/**��ȡsocket������
*@param   socketfd: ����socket�ӿڷ��ص�socket������
@param      level: ֧��SOL_SOCKET/IPPROTO_TCP
@param      optname:  SOL_SOCKET��ӦoptnameΪ SO_DEBUG/SO_OOBINLINE/SO_SNDTIMEO/SO_RCVTIMEO/SO_RCVBUF/SO_SNDBUF
                      IPPROTO_TCP��ӦoptnameΪ SO_TCP_SACKDISABLE/SO_TCP_NODELAY
@param      optval_p:
@param      optlen_p:
*@return  0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*
**/          

int getsockopt(int socketfd, 
                        int level, 
                        int optname,
                        void *optval_p, 
                        socklen_t* optlen_p)
{
    return IVTBL(getsockopt)(socketfd, level, optname, optval_p, optlen_p);
}       
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
                      socklen_t addrlen)
{
    return IVTBL(bind)(socketfd, my_addr, addrlen);
}                      
/**�����ͷ������˵�����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      addr:   ָ����������ַ�Ͷ˿�
@param      addrlen:  sizeof(struct sockaddr)
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*           
**/                                      
int connect(int socketfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return IVTBL(connect)(socketfd, addr, addrlen);
}
/**����socket���ӣ�һ�����������������ͻ��˵�����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      backlog:   0
*@return	0:  ��ʾ�ɹ�
            <0  ��ʾ�д���
*           
**/                             
int listen(int socketfd, 
                       int backlog)

{
    return IVTBL(listen)(socketfd, backlog);
}
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
                        socklen_t *addrlen)
{
    return IVTBL(accept)(socketfd, addr, addrlen);
}
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
                      int flags)
{
    return IVTBL(recv)(socketfd, buf, len, flags);
}                      
/**����ָ��ip��ַ�����������ݣ�һ������UDP��ȡ����
*@param		socketfd:	����socket�ӿڷ��ص�socket������
@param      buf:   ���ڴ�����ݵĻ���
@param      len:   buf�ĳ���
@param      flags: ��֧��0
@param      addr:  ֧��ip��ַ�Ͷ˿�
@param      addrlen: sizeof(struct sockaddr)

*@return	>0: ʵ���յ������ݳ���
            =0:  �Է��Ѿ��Ͽ�����
            <0:  ��ȡ����
**/   

int recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen)
{
    return IVTBL(recvfrom)(sockfd, buf, len, flags, src_addr, addrlen);
}
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
                      int flags)
{
    return IVTBL(send)(socketfd, msg, len, flags);
}                      
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
                        socklen_t tolen)
{
    return IVTBL(sendto)(socketfd, buf, len, flags, to_p, tolen);
}
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
                        struct timeval *timeout)
{
    return IVTBL(select)(maxfdp1, readset, writeset, exceptset, timeout);
}
/**��ȡsocket�Ĵ���ֵ
*@param		socketfd:	����socket�ӿڷ��ص�socket������
*@return	[EBADF �� ENO_RECOVERY]
**/                                       
int socket_errno(int socketfd)
{
    return IVTBL(socket_errno)(socketfd);
}


/* Here for now until needed in other places in lwIP */
#ifndef isprint
#define in_range(c, lo, up)  ((UINT8)c >= lo && (UINT8)c <= up)
#define isprint(c)           in_range(c, 0x20, 0x7f)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c)           in_range(c, 'a', 'z')
#define isspace(c)           (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v')
#endif



/**
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 *
 * @param cp IP address in ascii represenation (e.g. "127.0.0.1")
 * @param addr pointer to which to save the ip address in network order
 * @return 1 if cp could be converted to addr, 0 on failure
 */
int
ipaddr_aton(const char *cp, ip_addr_t *addr)
{
  UINT32 val;
  UINT8 base;
  char c;
  UINT32 parts[4];
  UINT32 *pp = parts;

  c = *cp;
  for (;;) {
    /*
     * Collect number up to ``.''.
     * Values are specified as for C:
     * 0x=hex, 0=octal, 1-9=decimal.
     */
    if (!isdigit(c))
      return (0);
    val = 0;
    base = 10;
    if (c == '0') {
      c = *++cp;
      if (c == 'x' || c == 'X') {
        base = 16;
        c = *++cp;
      } else
        base = 8;
    }
    for (;;) {
      if (isdigit(c)) {
        val = (val * base) + (int)(c - '0');
        c = *++cp;
      } else if (base == 16 && isxdigit(c)) {
        val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
        c = *++cp;
      } else
        break;
    }
    if (c == '.') {
      /*
       * Internet format:
       *  a.b.c.d
       *  a.b.c   (with c treated as 16 bits)
       *  a.b (with b treated as 24 bits)
       */
      if (pp >= parts + 3) {
        return (0);
      }
      *pp++ = val;
      c = *++cp;
    } else
      break;
  }
  /*
   * Check for trailing characters.
   */
  if (c != '\0' && !isspace(c)) {
    return (0);
  }
  /*
   * Concoct the address according to
   * the number of parts specified.
   */
  switch (pp - parts + 1) {

  case 0:
    return (0);       /* initial nondigit */

  case 1:             /* a -- 32 bits */
    break;

  case 2:             /* a.b -- 8.24 bits */
    if (val > 0xffffffUL) {
      return (0);
    }
    val |= parts[0] << 24;
    break;

  case 3:             /* a.b.c -- 8.8.16 bits */
    if (val > 0xffff) {
      return (0);
    }
    val |= (parts[0] << 24) | (parts[1] << 16);
    break;

  case 4:             /* a.b.c.d -- 8.8.8.8 bits */
    if (val > 0xff) {
      return (0);
    }
    val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
    break;
  default:
    return 0;
    break;
  }
  if (addr) {
    addr->addr = htonl(val);
  }
  return (1);
}

/**
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 *
 * @param cp IP address in ascii represenation (e.g. "127.0.0.1")
 * @return ip address in network order
 */
UINT32
ipaddr_addr(const char *cp)
{
  ip_addr_t val;

  if (ipaddr_aton(cp, &val)) {
    return val.addr;
  }
  return (INADDR_NONE);
}

/**
 * Same as ipaddr_ntoa, but reentrant since a user-supplied buffer is used.
 *
 * @param addr ip address in network order to convert
 * @param buf target buffer where the string is stored
 * @param buflen length of buf
 * @return either pointer to buf which now holds the ASCII
 *         representation of addr or NULL if buf was too small
 */
char *ipaddr_ntoa_r(const ip_addr_t *addr, char *buf, int buflen)
{
  UINT32 s_addr;
  char inv[3];
  char *rp;
  UINT8 *ap;
  UINT8 rem;
  UINT8 n;
  UINT8 i;
  int len = 0;

  s_addr = addr->addr;

  rp = buf;
  ap = (UINT8 *)&s_addr;
  for(n = 0; n < 4; n++) {
    i = 0;
    do {
      rem = *ap % (UINT8)10;
      *ap /= (UINT8)10;
      inv[i++] = '0' + rem;
    } while(*ap);
    while(i--) {
      if (len++ >= buflen) {
        return NULL;
      }
      *rp++ = inv[i];
    }
    if (len++ >= buflen) {
      return NULL;
    }
    *rp++ = '.';
    ap++;
  }
  *--rp = 0;
  return buf;
}

/**
 * Convert numeric IP address into decimal dotted ASCII representation.
 * returns ptr to static buffer; not reentrant!
 *
 * @param addr ip address in network order to convert
 * @return pointer to a global static (!) buffer that holds the ASCII
 *         represenation of addr
 */
char *
ipaddr_ntoa(const ip_addr_t *addr)
{
  static char str[16];
  return ipaddr_ntoa_r(addr, str, 16);
}



