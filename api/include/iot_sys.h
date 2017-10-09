#ifndef __IOT_SYS_H__
#define __IOT_SYS_H__

#include "iot_os.h"


/**
 * @defgroup iot_sdk_sys ϵͳ�ӿ�
 * @{
 */
/**@example demo_ota/src/demo_ota.c
* fs�ӿ�ʾ��
*/ 

/**ota����new app���ļ���������֪�ײ���Ҫ���ļ���ȡ�����µĳ���
*@param		newAPPFile:		�³����ļ� 
*@return	TRUE: �ɹ�   FALSE: ʧ��
**/
BOOL iot_ota_newapp(              
                    CONST WCHAR* newAPPFile
               );

               
/**��char����ת��ΪWCHAR�����������Ϊiot_fs_open_file�Ƚӿڵ��ļ�������
*@param     dst:        ת��������
*@param     src:        �ȴ�ת�����ַ���
*@return    ����dst�׵�ַ
**/ 
WCHAR* iot_strtows(WCHAR* dst, const char* src);



/**@example demo_vat/src/demo_vat.c
* vat�ӿ�ʾ��
*/ 
/**������������ATͨ���Ļص�����
*@param		vatHandle:  ����AT�����ϱ�����AT���������صĻص�����
*@return	TRUE: �ɹ�   FALSE: ʧ��
**/
BOOL iot_vat_init(PAT_MESSAGE vatHandle);

/**��������AT����
*@param		cmdStr:  AT�����ַ���
*@param   	cmdLen:  AT�����
*@return	TRUE: �ɹ�   FALSE: ʧ��
*@note      ע�⣬AT�����ַ���cmdStr����Ҫ����"\r\n"����"\r"��β
**/
BOOL iot_vat_sendATcmd(UINT8* cmdStr, UINT16 cmdLen);

/** @}*/






#endif

