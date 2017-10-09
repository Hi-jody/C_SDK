#ifndef __IOT_DEBUG_H__
#define __IOT_DEBUG_H__

#include "iot_os.h"

/**
 * @defgroup iot_sdk_debug ���Խӿ�
 * @{
 */

/**������Ϣ��ӡ
**/
#define iot_debug_print g_s_InterfaceVtbl->print

/**assert����
*@param		condition:	��������
*@param		func:	    ���Ժ���
*@param		line:	    ����λ��
*@return	TURE: 	    �ɹ�
*           FALSE:      ʧ��
**/
VOID iot_debug_assert(                                            
                        BOOL condition,                  
                        CHAR *func,                      
                        UINT32 line                     
              );
/**��������쳣ʱ���豸ģʽ
*@param		mode:	OPENAT_FAULT_RESET ����ģʽ
                    OPENAT_FAULT_HANG  ����ģʽ
**/

VOID iot_debug_set_fault_mode(E_OPENAT_FAULT_MODE mode);

/** @}*/

#endif
