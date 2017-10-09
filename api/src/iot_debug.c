#include "iot_debug.h"


/*******************************************
**                 DEBUG                  **
*******************************************/

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
              )
{
    IVTBL(assert)(condition, func, line);
}


/**��������쳣ʱ���豸ģʽ
*@param	  mode:   OPENAT_FAULT_RESET ����ģʽ
				  OPENAT_FAULT_HANG  ����ģʽ
**/

VOID iot_debug_set_fault_mode(E_OPENAT_FAULT_MODE mode)
{
	IVTBL(set_fault_mode)(mode);
}

