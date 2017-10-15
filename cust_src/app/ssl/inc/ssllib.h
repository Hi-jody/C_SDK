#ifndef __SSL_LIB_H__
#define __SSL_LIB_H__

/*
 * ssllib.h�ӿڴ󲿷��ǽ���ֲ������axtlsԴ�벿�ֽӿ��ٴη�װ����Ҫ��ʹ����һЩĬ�����������
 * ���˱������SSL_RegSocketCallback�⣬�����ӿھ����Բ�ʹ�ã���ֻʹ��ssl.h��Ľӿڡ�
 * ssl.h�Ľӿڸ�ȫ�棬���ssllib.h��ĺ����޷������û�Ҫ����ʹ��ssl.h���ԭʼ�ӿ�
 * ���ԣ��� http://axtls.sourceforge.net/
 */

#include "os_port.h"
#include "ssl.h"
typedef int(*SocketAPI)(int SocketFd, void *Buf, uint16_t Len);
extern EXP_FUNC int STDCALL new_pem_obj(SSL_CTX *ssl_ctx, int is_cacert, char *where,
        int remain, const char *password);
extern EXP_FUNC int STDCALL do_obj(SSL_CTX *ssl_ctx, int obj_type,
        SSLObjLoader *ssl_obj, const char *password);
/**
 * @brief ע��SSL�������շ�����������Ĭ��ʹ��socket��ʽ��Ϊ����ATָ���û����ṩ�˽ӿڣ������ݵ��շ�����ATָ�����
 * @param SendFun ���ͺ���
 * @param ReceiveFun ���պ���
 * @return  ��
 */
void SSL_RegSocketCallback(SocketAPI SendFun, SocketAPI ReceiveFun);

/**
 * @brief ����һ��SSL���ƽṹ�壬û��Ĭ��KEY����Ҫ֮����SSL_LoadKey������֤������
 * @param NumSessions ����������Session������Ϊ0
 * @return  һ��SSL���ƽṹ��ĵ�ַָ��
 */
SSL_CTX * SSL_CreateCtrl(uint16_t NumSessions);

/**
 * @brief ɾ��һ��SSL���ƽṹ��
 * @param SSLCtrl ���ƽṹ��ĵ�ַָ��
 * @return ��
 */
void SSL_FreeCtrl(SSL_CTX *SSLCtrl);

/**
 * @brief ����һ��SSL���ӽṹ�壬����ʼSSL���ֹ��̡�
 * @param SSLCtrl [in] SSL���ƽṹ��.
 * @param ClientID [in] �����socket������socketID�������ATָ���·������0����·������ͨ����.
 * @param SessionID [in] һ�����32�ֽڵ�SessionID�����������Session�������Ч�����ڻָ��Ѿ������session
 * @param SessionIDSize SessionID����
 * @param Hostname [in] ������֤���������󲿷�����²���Ҫ����NULL
 * @param MaxFragmentSize [in] ���Ƭ�γ��ȣ��󲿷�����²���Ҫ����NULL���������ֵֻ��2^9, 2^10 .. 2^14
 * @return ����һ��SSL���ӽṹ��ĵ�ַָ��
 */
SSL * SSL_NewLink(
		SSL_CTX *SSLCtrl,
		int32_t ClientID,
		const uint8_t *SessionID,
		uint8_t SessionIDSize,
		const char **Hostname,
		uint16_t *MaxFragmentSize);

/**
 * @brief ���¿�ʼSSL���ֹ��̡�
 * @param SSLLink [in] SSL���ӽṹ��.
 * @return 0��ʾ�ɹ�������ʧ��
 */
int32_t SSL_ReHandshake(SSL *SSLLink);

/**
 * @brief �������ֽ��.
 * @param SSLLink [in] SSL���ӽṹ��ĵ�ַָ��.
 * @return 0��ʾ�ɹ�������ʧ��
 */
int32_t SSL_HandshakeStatus(const SSL *SSLLink);

/**
 * @brief ɾ��һ��SSL���ӽṹ�壬��ɾ��ǰ�����û�з��͹��ر�֪ͨ�����Զ��������ŵķ��������͹ر�֪ͨ
 * @param SSLLink SSL���ӽṹ��ĵ�ַָ��
 * @return ��
 */
void SSL_FreeLink(SSL *SSLLink);

/**
 * @brief ��������ɺ󣬽������ݱ���ʹ�ô˽ӿڣ��Ӷ���ȡ���ܺ������
 * @param SSLLink [in] SSL���ӽṹ��ĵ�ַָ��.
 * @param InData [out] ���ܺ������ָ���ַ��ע�⣬�ò�������Ҫmalloc�ռ䣬Ҳ��Ҫfree�ռ䣬
 * ��NULL��ʾ�����ݣ�NULL��ʾû�����ݡ�
 * @return  >0 ���ܺ����ݳ���, =0 ���ݻ�û�н����꣬��Ҫ�ٴζ�ȡ�� <0 �д���
 */
int32_t SSL_Read(SSL *SSLLink, uint8_t **InData);

/**
 * @brief ��������ɺ󣬷������ݱ���ʹ�ô˽ӿڣ�����δ���ܵ����ݣ������ܷ��ͣ�ע��ýӿ���������
 * @param SSLLink [in] SSL���ӽṹ��ĵ�ַָ��.
 * @param OutData [in] ��Ҫ���͵�δ��������ָ��
 * @param OutLen [in] ��Ҫ���͵�δ�������ݳ���.
 * @return >0ʵ�ʷ��͵ĳ��� <0 �д���
 */
int32_t SSL_Write(SSL *SSLLink, const uint8_t *OutData, uint16_t OutLen);

/**
 * @brief ����֤�����RSAkey��������ļ���ʽ����ҪԤ�ȴ��ļ����ȡȫ��ԭʼ���ݵ��ڴ�
 * @param SSLCtrl [in] SSLCtrl ���ƽṹ��ĵ�ַָ��
 * @param Type [in] ���ص��������ͣ�ֻ����
 * - SSL_OBJ_X509_CERT (no password required) �ͻ��˵�֤�飬���ڷ�������֤�ͻ��ˣ��󲿷��������Ҫ��Ŀǰ�漰�����н���ʱ������Ҫ
 * - SSL_OBJ_X509_CACERT (no password required) ��֤������֤���õ�CA֤�飬�������Ǳ����
 * - SSL_OBJ_RSA_KEY (AES128/AES256 PEM encryption supported)
 * - SSL_OBJ_PKCS8 (RC4-128 encrypted data supported)
 * - SSL_OBJ_PKCS12 (RC4-128 encrypted data supported).
 * @param Data [in] ���ص�����ָ�룬������16�������ݣ�Ҳ������ASCII�ַ���.
 * @param Len [in] ���ݳ���
 * @param Password [in] ����Ǽ��ܵ�֤����Ҫ���������ܣ�������NULL
 * @return 0�ɹ� ����ʧ��
 */
int32_t SSL_LoadKey(SSL_CTX *SSLCtrl, int32_t Type, const uint8_t *Data, int32_t Len, const int8_t *Password);

#endif
