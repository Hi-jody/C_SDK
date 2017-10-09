#ifndef __IOT_SPI_H__
#define __IOT_SPI_H__

#include "iot_os.h"

/**
 * @ingroup iot_sdk_device ����ӿ�
 * @{
 */
/**
 * @defgroup iot_sdk_spi spi�ӿ�
 * @{
 */

/**����spi
*@param		port:		SPI ���
*@param		cfg:		��ʼ������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_spi_config(
                        E_AMOPENAT_SPI_PORT  port,         
                        T_AMOPENAT_SPI_PARAM *cfg        
                  );

/**��ȡspi����
*@param		port:		SPI ���
*@param		buf:		�洢���ݵ�ַ
*@param		bufLen:		�洢�ռ䳤��
*@return	UINT32: 	ʵ�ʶ�ȡ����
**/
UINT32 iot_spi_read(                                       
                        E_AMOPENAT_SPI_PORT port,         
                        UINT8* buf,                      
                        UINT32 bufLen                      
                  );

/**д��spi����
*@param		port:		SPI ���
*@param		buf:		д�����ݵ�ַ
*@param		bufLen:		д�����ݳ���
*@return	UINT32: 	ʵ��д�볤��
**/
UINT32 iot_spi_write(                                       
                        E_AMOPENAT_SPI_PORT port,        
                        CONST UINT8* buf,                  
                        UINT32 bufLen                      
                   );

/**spiȫ˫����д
*@note      ȫ˫����ʽ��д����д������ͬ
*@param		port:		SPI ���
*@param		txBuf:		д����
*@param		rxBuf:		������
*@param		len:		��д����
*@return	UINT32: 	ʵ��д�볤��
**/
UINT32 iot_spi_rw(                                       
                        E_AMOPENAT_SPI_PORT port,         
                        CONST UINT8* txBuf,               
                        UINT8* rxBuf,                       
                        UINT32 len                          
                );

/**�ر�spi
*@param		port:		SPI ���
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_spi_close(
                        E_AMOPENAT_SPI_PORT  port
                );    

/** @}*/
/** @}*/

#endif



