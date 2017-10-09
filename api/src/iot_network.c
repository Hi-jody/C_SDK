#include "iot_flash.h"

extern T_AMOPENAT_INTERFACE_VTBL * g_s_InterfaceVtbl;
#define IVTBL(func) (g_s_InterfaceVtbl->func)


/**��ȡ����״̬
*@param     status:   ��������״̬
*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
**/                                
BOOL iot_network_get_status (
                            T_OPENAT_NETWORK_STATUS* status
                            )
{
    return IVTBL(network_get_status)(status);
}                            
/**��������״̬�ص�����
*@param     indCb:   �ص�����
*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
**/                            
BOOL iot_network_set_cb    (
                            F_OPENAT_NETWORK_IND_CB indCb
                          )
{
    return IVTBL(network_set_cb)(indCb);
}                          
/**�����������ӣ�ʵ��Ϊpdp��������
*@param     status:   ��������״̬
*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
@note      �ú���Ϊ�첽���������غ󲻴����������Ӿͳɹ��ˣ�indCb��֪ͨ�ϲ�Ӧ�����������Ƿ�ɹ������ӳɹ�������OPENAT_NETWORK_LINKED״̬
           ����socket����֮ǰ����Ҫ������������
           ��������֮ǰ��״̬��ҪΪOPENAT_NETWORK_READY״̬�����������ʧ��
**/                          
BOOL iot_network_connect     (
                            T_OPENAT_NETWORK_CONNECT* connectParam
                          )
{
    return IVTBL(network_connect)(connectParam);
}                          
/**�Ͽ��������ӣ�ʵ��Ϊpdpȥ����
*@param     flymode:   ��ʱ��֧��

*@return    TRUE:    �ɹ�
            FLASE:   ʧ��
@note      �ú���Ϊ�첽���������غ󲻴����������������ͶϿ��ˣ�indCb��֪ͨ�ϲ�Ӧ��
           ���ӶϿ�������״̬��ص�OPENAT_NETWORK_READY״̬
           ��ǰ����socket����Ҳ��ʧЧ����Ҫclose��
**/                                        
BOOL iot_network_disconnect  (
                            BOOL flymode
                          )
{
    return IVTBL(network_disconnect)(FALSE);
}                          

