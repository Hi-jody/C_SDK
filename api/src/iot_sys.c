#include "iot_sys.h"


/**ota����new app���ļ���������֪�ײ���Ҫ���ļ���ȡ�����µĳ���
*@param		newAPPFile:		�³����ļ� 
*@return	TRUE: �ɹ�   FALSE: ʧ��
**/
BOOL iot_ota_newapp(              
                    CONST char* newAPPFile
               )
{
    return IVTBL(flash_set_newapp)(newAPPFile);
}


/**��char����ת��ΪWCHAR�����������Ϊiot_fs_open_file�Ƚӿڵ��ļ�������
*@param     dst:        ת��������
*@param     src:        �ȴ�ת�����ַ���
*@return    ����dst�׵�ַ
**/ 
WCHAR* iot_strtows(WCHAR* dst, const char* src)
{
   WCHAR* rlt = dst;
   while(*src)
   {
       *dst++ = *src++;
   }
   *dst = 0;
   
   return (rlt);
}


/**������������ATͨ���Ļص�����
*@param		vatHandle:  ����AT�����ϱ�����AT���������صĻص�����
*@return	TRUE: �ɹ�   FALSE: ʧ��
**/
BOOL iot_vat_init(PAT_MESSAGE vatHandle)
{
	return IVTBL(init_at)(vatHandle);
}

/**��������AT����
*@param		cmdStr:  AT�����ַ���
*@return	cmdLen:  AT�����
*@note      ע�⣬AT�����ַ���cmdStr����Ҫ����\r\n����\r��β
**/
BOOL iot_vat_sendATcmd(UINT8* cmdStr, UINT16 cmdLen)
{
	return IVTBL(send_at_command)(cmdStr, cmdLen);
}

