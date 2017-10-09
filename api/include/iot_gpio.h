#ifndef __IOT_GPIO_H__
#define __IOT_GPIO_H__

#include "iot_os.h"

/**
 * @defgroup iot_sdk_device ����ӿ�
 * @{
 */
	/**@example demo_gpio/src/demo_gpio.c
	* gpio�ӿ�ʾ��
	*/ 

/**
 * @defgroup iot_sdk_gpio GPIO�ӿ�
 * @{
 */

/**����gpio 
*@param		port:		GPIO���
*@param		cfg:		������Ϣ
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_gpio_config(                          
                        E_AMOPENAT_GPIO_PORT port,  
                        T_AMOPENAT_GPIO_CFG *cfg  
                   );

/**����gpio 
*@param		port:		GPIO���
*@param		value:		0 or 1
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_gpio_set(                               
                        E_AMOPENAT_GPIO_PORT port,  
                        UINT8 value                 
                );

/**��ȡgpio 
*@param		port:		GPIO���
*@param		value:		0 or 1
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/			
BOOL iot_gpio_read(                            
                        E_AMOPENAT_GPIO_PORT port, 
                        UINT8* value             
                  );

/**�ر�gpio 
*@param		port:		GPIO���
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/	
BOOL iot_gpio_close(                            
                        E_AMOPENAT_GPIO_PORT port
                  );

/** @}*/
/** @}*/


#endif


