#ifndef __IOT_I2C_H__
#define __IOT_I2C_H__

#include "iot_os.h"

/**
 * @ingroup iot_sdk_device ����ӿ�
 * @{
 */
/**
 * @defgroup iot_sdk_i2c i2c�ӿ�
 * @{
 */

/**����i2c
*@param		port:		I2C ���
*@param		param:		��ʼ������
*@return	TRUE:       �ɹ�
*	        FALSE:      ʧ��
**/
BOOL iot_i2c_open(
                        E_AMOPENAT_I2C_PORT  port,         
                        T_AMOPENAT_I2C_PARAM *param        
                  );

/**�ر�i2c
*@param		port:		I2C ���
*@return	TRUE:       �ɹ�
*	        FALSE:      ʧ��
**/
BOOL iot_i2c_close(
                        E_AMOPENAT_I2C_PORT  port          
                  );

/**д��i2c����
*@param		port:		    I2C ���
*@param		salveAddr:		���豸��ַ
*@param		pRegAddr:		�Ĵ�����ַ
*@param		buf:		    д�����ݵ�ַ
*@param		bufLen:		    д�����ݳ���
*@return	UINT32:         ʵ��д�볤��
**/
UINT32 iot_i2c_write(                                    
                        E_AMOPENAT_I2C_PORT port,        
                        UINT8 salveAddr,
                        CONST UINT8 *pRegAddr,          
                        CONST UINT8* buf,               
                        UINT32 bufLen                    
                   );

/**��ȡi2c����
*@param		port:		    I2C ���
*@param		slaveAddr:		���豸��ַ
*@param		pRegAddr:		�Ĵ�����ַ
*@param		buf:		    �洢���ݵ�ַ
*@param		bufLen:		    �洢�ռ䳤��
*@return	UINT32:         ʵ�ʶ�ȡ����
**/
UINT32 iot_i2c_read(                                        
                        E_AMOPENAT_I2C_PORT port,        
                        UINT8 slaveAddr, 
                        CONST UINT8 *pRegAddr,             
                        UINT8* buf,                      
                        UINT32 bufLen                      
                  );

/** @}*/
/** @}*/

#endif

