#ifndef __SSL_LIB_H__
#define __SSL_LIB_H__

/*
 * ssllib.h接口大部分是将移植过来的axtls源码部分接口再次封装，主要是使用了一些默认输入参数。
 * 除了必须调用SSL_RegSocketCallback外，其他接口均可以不使用，而只使用ssl.h里的接口。
 * ssl.h的接口更全面，如果ssllib.h里的函数无法满足用户要求，请使用ssl.h里的原始接口
 * 特性：见 http://axtls.sourceforge.net/
 */

#include "os_port.h"
#include "ssl.h"
typedef int(*SocketAPI)(int SocketFd, void *Buf, uint16_t Len);

/**
 * @brief 注册SSL的数据收发函数，由于默认使用socket形式，为方便AT指令用户，提供此接口，将数据的收发交由AT指令完成
 * @param SendFun 发送函数
 * @param ReceiveFun 接收函数
 * @return  无
 */
void SSL_RegSocketCallback(SocketAPI SendFun, SocketAPI ReceiveFun);

/**
 * @brief 创建一个SSL控制结构体
 * @param NumSessions 最多允许缓存的Session，可以为0
 * @return  一个SSL控制结构体的地址指针
 */
SSL_CTX * SSL_CreateCtrl(uint16_t NumSessions);

/**
 * @brief 删除一个SSL控制结构体
 * @param SSLCtrl 控制结构体的地址指针
 * @return 无
 */
void SSL_FreeCtrl(SSL_CTX *SSLCtrl);

/**
 * @brief 创建一个SSL连接结构体，并开始SSL握手过程。
 * @param SSLCtrl [in] SSL控制结构体.
 * @param ClientID [in] 如果是socket，则是socketID，如果是AT指令，单路链接填0，多路链接填通道号.
 * @param SessionID [in] 一个最多32字节的SessionID，如果启动了Session缓存才有效，用于恢复已经保存的session
 * @param SessionIDSize SessionID长度
 * @param Hostname [in] 用于验证的域名，大部分情况下不需要，填NULL
 * @param MaxFragmentSize [in] 最大片段长度，大部分情况下不需要，填NULL，可以填的值只有2^9, 2^10 .. 2^14
 * @return 返回一个SSL连接结构体的地址指针
 */
SSL * SSL_NewHandshake(
		SSL_CTX *SSLCtrl,
		int32_t ClientID,
		const uint8_t *SessionID,
		uint8_t SessionIDSize,
		const char *Hostname,
		uint16_t *MaxFragmentSize);

/**
 * @brief 重新开始SSL握手过程。
 * @param SSLLink [in] SSL连接结构体.
 * @return 0表示成功，其他失败
 */
int32_t SSL_ReHandshake(SSL *SSLLink);

/**
 * @brief 返回握手结果.
 * @param SSLLink [in] SSL连接结构体的地址指针.
 * @return 0表示成功，其他失败
 */
int32_t SSL_HandshakeStatus(const SSL *SSLLink);

/**
 * @brief 删除一个SSL连接结构体，在删除前，如果没有发送过关闭通知，会自动对连接着的服务器发送关闭通知
 * @param SSLLink SSL连接结构体的地址指针
 * @return 无
 */
void SSL_FreeLink(SSL *SSLLink);

/**
 * @brief 在握手完成后，接收数据必须使用此接口，从而获取解密后的数据
 * @param SSLLink [in] SSL连接结构体的地址指针.
 * @param InData [out] 解密后的数据指针地址，注意，该参数不需要malloc空间，也不要free空间，
 * 非NULL表示有数据，NULL表示没有数据。
 * @return  >0 解密后数据长度, =0 没有数据 <0 有错误
 */
int32_t SSL_Read(SSL *SSLLink, uint8_t **InData);

/**
 * @brief 在握手完成后，发送数据必须使用此接口，输入未加密的数据，并加密发送，注意该接口阻塞发送
 * @param SSLLink [in] SSL连接结构体的地址指针.
 * @param OutData [in] 需要发送的未加密数据指针
 * @param OutLen [in] 需要发送的未加密数据长度.
 * @return >0实际发送的长度 <0 有错误
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
