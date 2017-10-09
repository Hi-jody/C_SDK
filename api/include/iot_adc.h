#ifndef __IOT_ADC_H__
#define __IOT_ADC_H__

#include "iot_os.h"

/**
 * @ingroup iot_sdk_device ����ӿ�
 * @{
 */
/**
 * @defgroup iot_sdk_adc adc�ӿ�
 * @{
 */

/**ADC��ʼ�� 
*@param		chanle:		adcͨ��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_adc_init(
                        E_AMOPENAT_ADC_CHANNEL chanle
                );


/**��ȡADC����
*@note ADCֵ������Ϊ��, ��ѹֵ������Ϊ��
*@param		chanle:		adcͨ��
*@param		adcValue:	ADCֵ������Ϊ��
*@param		voltage:	��ѹֵ������Ϊ��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_adc_read(
                        E_AMOPENAT_ADC_CHANNEL chanle,    
                        UINT16* adcValue,                
                        UINT16* voltage                    
                );

/** @}*/
/** @}*/





#endif

