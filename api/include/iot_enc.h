#ifndef __IOT_ENC_H__
#define __IOT_ENC_H__

#include "iot_os.h"


/**
 * @defgroup iot_sdk_enc ���ܿ��ӿ�
 * @{
 */

/**������Կ��Ϣ
*@param		encInfo:	������Ϣ������
*@param		len:	    ������Ϣ������
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_enc_set_info(                        
                    UINT8 *encInfo,
                    UINT32 len
          );

/**��ȡ��Կ��Ϣ
*@param		encInfo:	������Ϣ�Ŀռ�
*@param		len:	    ������Ϣ�Ŀռ䳤��
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_enc_get_info(                   
                    UINT8 *encInfo,
                    UINT32 len
          );

/**��ȡ����У����
*@return	����У����
**/
UINT8 iot_enc_get_result(                  
                    void
          );

/**��ȡ������
*@return ����У�鿨���� 
         0: δ֪
         1: ���ܿ�
         2: ��ͨ��
**/
UINT8 iot_enc_get_cardtype(                   
                    void
          );
          

/**��Կ֪ͨ�ӿ�
*@note iot_enc_set_info���ú���Կ��Ϣ��, Ҫ�����������֪ͨ
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_enc_set_data_ok(                    
                    void
          );

/** @}*/


#endif