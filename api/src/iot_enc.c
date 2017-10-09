#include "iot_enc.h"


/*******************************************
**               ���ܿ�����               **
*******************************************/

/**������Կ��Ϣ
*@param		encInfo:	������Ϣ������
*@param		len:	    ������Ϣ������
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_enc_set_info(                       
                    UINT8 *encInfo,
                    UINT32 len
          )
{
    return IVTBL(set_encinfo)(encInfo, len);
}

/**��ȡ��Կ��Ϣ
*@param		encInfo:	������Ϣ�Ŀռ�
*@param		len:	    ������Ϣ�Ŀռ䳤��
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_enc_get_info(                        
                    UINT8 *encInfo,
                    UINT32 len
          )
{
    return IVTBL(get_encinfo)(encInfo, len);
}

/**��ȡ����У����
*@return	����У����
**/
UINT8 iot_enc_get_result(                        
                    void
          )
{
    return IVTBL(get_encresult)();
}


/**��ȡ������
*@return ����У�鿨���� 
         0: δ֪
         1: ���ܿ�
         2: ��ͨ��
**/
UINT8 iot_enc_get_cardtype(                  
                    void
          )
{
    return IVTBL(get_cardtype)();
}

/**��Կ֪ͨ�ӿ�
*@note iot_enc_set_info���ú���Կ��Ϣ��, Ҫ�����������֪ͨ
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_enc_set_data_ok(                     
                    void
          )
{
    return IVTBL(set_enc_data_ok)();
}