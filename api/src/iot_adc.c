#include "iot_adc.h"

/**ADC��ʼ�� 
*@param		chanle:		adcͨ��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_adc_init(
                        E_AMOPENAT_ADC_CHANNEL chanle
                )
{
    return IVTBL(init_adc)(chanle);
}

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
                )
{
    return IVTBL(read_adc)(chanle, adcValue, voltage);
}
