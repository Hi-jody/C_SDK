#ifndef __IOT_NETWORK_H__
#define __IOT_NETWORK_H__

#include "am_openat.h"

/**
 * @defgroup iot_sdk_network ����ӿ�
 * @{
 */
/**��ȡ����״̬
*@param     status:   ��������״̬
*@return    TRUE:    �ɹ�
            FLASE:   ʧ��            
**/                                
BOOL iot_network_get_status (
                            T_OPENAT_NETWORK_STATUS* status
                            );
/**��������״̬�ص�����
*@param     indCb:   �ص�����
*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
**/                            
BOOL iot_network_set_cb    (
                            F_OPENAT_NETWORK_IND_CB indCb
                          );
/**�����������ӣ�ʵ��Ϊpdp��������
*@param     connectParam:  �������Ӳ�������Ҫ����APN��username��passwrd��Ϣ
*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
@note      �ú���Ϊ�첽���������غ󲻴����������Ӿͳɹ��ˣ�indCb��֪ͨ�ϲ�Ӧ�����������Ƿ�ɹ������ӳɹ�������OPENAT_NETWORK_LINKED״̬
           ����socket����֮ǰ����Ҫ������������
           ��������֮ǰ��״̬��ҪΪOPENAT_NETWORK_READY״̬�����������ʧ��
**/                          
BOOL iot_network_connect     (
                            T_OPENAT_NETWORK_CONNECT* connectParam
                          );
/**�Ͽ��������ӣ�ʵ��Ϊpdpȥ����
*@param     flymode:   ��ʱ��֧�֣�����ΪFLASE

*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
@note      �ú���Ϊ�첽���������غ󲻴����������������ͶϿ��ˣ�indCb��֪ͨ�ϲ�Ӧ��
           ���ӶϿ�������״̬��ص�OPENAT_NETWORK_READY״̬
           ��ǰ����socket����Ҳ��ʧЧ����Ҫclose��
**/                                        
BOOL iot_network_disconnect  (
                            BOOL flymode
                          );

/** @}*/

#endif

