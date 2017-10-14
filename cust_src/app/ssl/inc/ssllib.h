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

/**
 * @brief ע��SSL�������շ�����������Ĭ��ʹ��socket��ʽ��Ϊ����ATָ���û����ṩ�˽ӿڣ������ݵ��շ�����ATָ�����
 * @param SendFun ���ͺ���
 * @param ReceiveFun ���պ���
 * @return  ��
 */
void SSL_RegSocketCallback(SocketAPI SendFun, SocketAPI ReceiveFun);

/**
 * @brief ����һ��SSL���ƽṹ��
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
SSL * SSL_NewHandshake(
		SSL_CTX *SSLCtrl,
		int32_t ClientID,
		const uint8_t *SessionID,
		uint8_t SessionIDSize,
		const char *Hostname,
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
 * @return  >0 ���ܺ����ݳ���, =0 û������ <0 �д���
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
 * @brief Process binary data.
 * These are temporary objects that are used to load private keys,
 * certificates etc into memory.
 * @param ssl_ctx [in] The client/server context.
 * @param obj_type [in] The format of the memory data.
 * @param data [in] The binary data to be loaded.
 * @param len [in] The amount of data to be loaded.
 * @param password [in] The password used. Can be null if not required.
 * @return SSL_OK if all ok
 * @see ssl_obj_load for more details on obj_type.
 */
int32_t ssl_obj_memory_load(SSL_CTX *ssl_ctx, int obj_type, const uint8_t *data, int len, const char *password);

/**
 * @brief Process binary data.
 * These are temporary objects that are used to load private keys,
 * certificates etc into memory.
 * @param ssl_ctx [in] The client/server context.
 * @param obj_type [in] The format of the memory data.
 * @param data [in] The binary data to be loaded.
 * @param len [in] The amount of data to be loaded.
 * @param password [in] The password used. Can be null if not required.
 * @return SSL_OK if all ok
 * @see ssl_obj_load for more details on obj_type.
 */
int32_t ssl_obj_memory_load(SSL_CTX *ssl_ctx, int obj_type, const uint8_t *data, int len, const char *password);

#endif
