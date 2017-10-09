#ifndef __IOT_UART_H__
#define __IOT_UART_H__

#include "iot_os.h"
/**
 * @ingroup iot_sdk_device ����ӿ�
 * @{
 */
/**
 * @defgroup iot_sdk_uart ���ڽӿ�
 * @{
 */
/**@example demo_uart/src/demo_uart.c
* uart�ӿ�ʾ��
*/ 

/**��uart
*@param		port:		UART ���
*@param		cfg:		������Ϣ
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_uart_config(
                        E_AMOPENAT_UART_PORT port,       
                        T_AMOPENAT_UART_PARAM *cfg         
                   );

/**�ر�uart
*@param		port:		UART ���
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_uart_close(
                        E_AMOPENAT_UART_PORT port          
                   );


/**��uart
*@param		port:		UART ���
*@param		buf:		�洢���ݵ�ַ
*@param		bufLen:		�洢�ռ䳤��
*@param		timeoutMs:	��ȡ��ʱ ms
*@return	UINT32:     ʵ�ʶ�ȡ����
**/
UINT32 iot_uart_read(                                       
                        E_AMOPENAT_UART_PORT port,         
                        UINT8* buf,                       
                        UINT32 bufLen,                      
                        UINT32 timeoutMs                  
                   );

/**дuart
*@param		port:		UART ���
*@param		buf:		д�����ݵ�ַ
*@param		bufLen:		д�����ݳ���
*@return	UINT32:     ʵ�ʶ�ȡ����
**/
UINT32 iot_uart_write(                                      
                        E_AMOPENAT_UART_PORT port,        
                        UINT8* buf,                         
                        UINT32 bufLen                       
                    );

/**uart�����ж�ʹ��
*@param		port:		UART ���
*@param		enable:		�Ƿ�ʹ��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_uart_enable_rx_int(
                        E_AMOPENAT_UART_PORT port,       
                        BOOL enable                      
                            );


/**host uart��ʼ��
*@param		hostCallback:		host uart�ص�����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_uart_host_init(PHOST_MESSAGE hostCallback);

/**host uartд����
*@param		data:		д���ݵ�ַ
*@param		len:		д���ݳ���
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_uart_host_send_data(uint8 *data, uint32 len);

/** @}*/
/** @}*/
#endif

