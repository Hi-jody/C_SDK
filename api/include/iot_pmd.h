#ifndef __IOT_PMD_H__
#define __IOT_PMD_H__

#include "iot_os.h"

/**
 * @defgroup iot_sdk_pmd ��Դ����ӿ�
 * @{
 */

/**����ʼ��
*@param		chrMode:		��緽ʽ
*@param		cfg:		    ������Ϣ
*@param		pPmMessage:		��Ϣ�ص�����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_pmd_init(     
                    E_AMOPENAT_PM_CHR_MODE chrMode,     
                    T_AMOPENAT_PMD_CFG*    cfg,       
                    PPM_MESSAGE            pPmMessage  
            );

/**��ȡ���״̬
*@param		batStatus:		���״̬
**/
VOID iot_pmd_get_batteryStatus(T_AMOPENAT_BAT_STATUS* batStatus);

/**��ȡ�����״̬
*@param		chrStatus:		�����״̬
**/
VOID iot_pmd_get_chargerStatus(T_AMOPENAT_CHARGER_STATUS* chrStatus);


/**��ѯ�����HW״̬�ӿ�
*@return	E_AMOPENAT_CHR_HW_STATUS: �����HW״̬�ӿ�
**/
E_AMOPENAT_CHR_HW_STATUS iot_pmd_get_chargerHwStatus(VOID);

/**��ѯ�����HW״̬�ӿ�
*@param		battStatus:		    ���״̬
*@param		battVolt:		    ��ѹֵ
*@param		battLevel:		    ��ѹ�ȼ�
*@param		chargerStatus:		�����״̬
*@param		chargeState:		���״̬
*@return	int:  ����0�ɹ�����ʧ��
**/
int iot_pmd_get_chg_param(BOOL *battStatus, u16 *battVolt, u8 *battLevel, BOOL *chargerStatus, u8 *chargeState);

/**��������
*@param		simStartUpMode:		����SIM����ʽ
*@param		nwStartupMode:		����Э��ջ��ʽ
*@return	TRUE: 	            �ɹ�
*           FALSE:              ʧ��
**/
BOOL iot_pmd_poweron_system(                                     
                    E_AMOPENAT_STARTUP_MODE simStartUpMode,
                    E_AMOPENAT_STARTUP_MODE nwStartupMode
                  );

/**�����ػ�
*@note �����ػ� �����ر�Э��ջ�͹���
**/
VOID iot_pmd_poweroff_system(VOID);

/**��LDO
*@param		ldo:		    ldoͨ��
*@param		level:		    0-7 0:�ر� 1~7��ѹ�ȼ�
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_pmd_poweron_ldo(                                       
                    E_AMOPENAT_PM_LDO    ldo,
                    UINT8                level          
               );

/**����˯��
**/
VOID iot_pmd_enter_deepsleep(VOID);

/**�˳�˯��
**/
VOID iot_pmd_exit_deepsleep(VOID);                               

/**��ȡ����ԭ��ֵ
*@return	E_AMOPENAT_POWERON_REASON: 	   ���ؿ���ԭ��ֵ
**/
E_AMOPENAT_POWERON_REASON iot_pmd_get_poweronCasue(VOID);

/** @}*/

#endif

