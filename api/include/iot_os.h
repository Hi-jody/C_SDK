#ifndef  __IOT_OS_H__
#define  __IOT_OS_H__



#include "am_openat.h"
#include "am_openat_fs.h"
#include "am_openat_system.h"
#include "am_openat_drv.h"

extern T_AMOPENAT_INTERFACE_VTBL * g_s_InterfaceVtbl;
#define IVTBL(func) (g_s_InterfaceVtbl->func)

/**
 * @defgroup iot_sdk_os ����ϵͳ�ӿ�
 * @{
 */

/**
 * @defgroup �߳̽ӿں������� �߳̽ӿں���
 * @{
 */
/**@example demo_os/src/demo_os.c
* os�ӿ�ʾ��
*/ 
/**�����߳�
*@note  nPriorityֵ�ķ�����0-20, ֵԽ�����ȼ�Խ��
*@param	pTaskEntry:		�߳�������
*@param	pParameter:		��Ϊ�������ݸ��߳�������
*@param	nStackSize: 	�߳�ջ��С
*@param	nPriority: 		�߳����ȼ����ò���Խ���߳����ȼ�Խ��
*@param nCreationFlags: �߳�������ǣ� ��ο�E_AMOPENAT_OS_CREATION_FLAG
*@param pTaskName: 		�߳�����
*@return	HANDLE: 	�����ɹ������߳̾��
**/
HANDLE iot_os_create_task(                         
                            PTASK_MAIN pTaskEntry,  
                            PVOID pParameter,         
                            UINT16 nStackSize,      
                            UINT8 nPriority,       
                            UINT16 nCreationFlags,     
                            PCHAR pTaskName       
						);

/**�����߳�
*@param	hTask:		�߳̾����create_task�ӿڷ���ֵ
*@param	pParameter:		��Ϊ�������ݸ��߳������������滻create_task�ӿڴ����pParameter����
**/
VOID iot_os_start_task(                           
                        HANDLE hTask,          
                        PVOID pParameter 
                      );

/**ֹͣ�߳�
*@param	hTask:		�߳̾��
**/		
VOID iot_os_stop_task(                              
                        HANDLE hTask        
                 );			

/**ɾ���߳�
*@param		hTask:		�߳̾��
*@return	TURE:		ɾ���̳߳ɹ�
*			FALSE: 		ɾ���߳�ʧ��
**/	
BOOL iot_os_delete_task(                           
                        HANDLE hTask        
                   );	

/**�����߳�
*@param		hTask:		�߳̾��
*@return	TURE: 		�����̳߳ɹ�
*			FALSE  : 	�����߳�ʧ��
**/
BOOL iot_os_suspend_task(                        
                            HANDLE hTask           
                        );

/**�ָ��߳�
*@param		hTask:		�߳̾��
*@return	TURE: 		�ָ��̳߳ɹ�
*			FALSE  : 	�ָ��߳�ʧ��
**/
BOOL iot_os_resume_task(                         
                        HANDLE hTask         
                   );

/**��ȡ��ǰ�߳�
*@return	HANDLE:		���ص�ǰ�߳̾��
*
**/				   
HANDLE iot_os_current_task(                
                            VOID
                          );	

/**��ȡ��ǰ�̴߳�����Ϣ
*@param		hTask:		�߳̾��
*@param		pTaskInfo:		�߳���Ϣ�洢�ӿ�
*@return	TURE: 		�ɹ�
*			FALSE  : 	ʧ��
**/
BOOL iot_os_get_task_info(                        
                            HANDLE hTask,           
                            T_AMOPENAT_TASK_INFO *pTaskInfo 
                         );			  
/** @}*/ 

/**
 * @defgroup ��Ϣ�ӿں������� ��Ϣ�ӿں���
 * @{
 */

/**��ȡ�߳���Ϣ
*@note ������
*@param		hTask:		�߳̾��
*@param		ppMessage:	�洢��Ϣָ��
*@return	TURE: 		�ɹ�
*			FALSE  : 	ʧ��
**/
BOOL iot_os_wait_message(                         
						HANDLE hTask,          
						PVOID* ppMessage      
					);
					
/**�����߳���Ϣ
*@note ��ӵ���Ϣ����β��
*@param		hTask:		�߳̾��
*@param		pMessage:	�洢��Ϣָ��
*@return	TURE: 		�ɹ�
*			FALSE  : 	ʧ��
**/					
BOOL iot_os_send_message(                         
						HANDLE hTask,          
						PVOID pMessage         
					);
					
/**���͸����ȼ��߳���Ϣ
*@note      ��ӵ���Ϣ����ͷ��
*@param		hTask:		�߳̾��
*@param		pMessage:	�洢��Ϣָ��
*@return	TURE: 		�ɹ�
*			FALSE  : 	ʧ��
**/						
BOOL iot_os_send_high_priority_message(             
						HANDLE hTask,           
						PVOID pMessage         
								  );								  

/**�����Ϣ�������Ƿ�����Ϣ
*@param		hTask:		�߳̾��
*@return	TURE: 		�ɹ�
*			FALSE  : 	ʧ��
**/								  
BOOL iot_os_available_message(                   
						HANDLE hTask       
						 );
/** @}*/ 

/**
 * @defgroup ʱ�䶨ʱ���ӿں������� ʱ�䶨ʱ���ӿں���
 * @{
 */

/**@example demo_timer/src/demo_timer.c
* timer�ӿ�ʾ��
*/ 


/**������ʱ��
*@param		pFunc:			��ʱ����ʱ������
*@param		pParameter:		��Ϊ�������ݸ���ʱ����ʱ������
*@return	HANDLE: 		���ض�ʱ�����
*			
**/	
HANDLE iot_os_create_timer(                         
						PTIMER_EXPFUNC pFunc,  
						PVOID pParameter       
					  );
					  
/**������ʱ��
*@param		hTimer:				��ʱ�������create_timer�ӿڷ���ֵ
*@param		nMillisecondes:		��ʱ��ʱ��
*@return	TURE: 				�ɹ�
*			FALSE  : 			ʧ��
**/								  
BOOL iot_os_start_timer(                            /* ������ʱ���ӿ� */
						HANDLE hTimer,          /* ��ʱ�������create_timer�ӿڷ���ֵ */
						UINT32 nMillisecondes   /*  */
				   );
				   
/**ֹͣ��ʱ��
*@param		hTimer:				��ʱ�������create_timer�ӿڷ���ֵ
*@return	TURE: 				�ɹ�
*			FALSE  : 			ʧ��
**/						   
BOOL iot_os_stop_timer(                             
						HANDLE hTimer   
				  );
				  
/**ɾ����ʱ��
*@param		hTimer:				��ʱ�������create_timer�ӿڷ���ֵ
*@return	TURE: 				�ɹ�
*			FALSE  : 			ʧ��
**/					  
BOOL iot_os_delete_timer(                           
						HANDLE hTimer           
					);
					
/**��鶨ʱ���Ƿ��Ѿ�����
*@param		hTimer:				��ʱ�������create_timer�ӿڷ���ֵ
*@return	TURE: 				�ɹ�
*			FALSE  : 			ʧ��
**/					
BOOL iot_os_available_timer(            
						HANDLE hTimer          
					   );
					   
					   
/**��ȡϵͳʱ��
*@param		pDatetime:		�洢ʱ��ָ��
*@return	TURE: 			�ɹ�
*			FALSE  : 		ʧ��
**/	
BOOL iot_os_get_system_datetime(                  
						T_AMOPENAT_SYSTEM_DATETIME* pDatetime
					   );
					   
/**����ϵͳʱ��
*@param		pDatetime:		�洢ʱ��ָ��
*@return	TURE: 			�ɹ�
*			FALSE  : 		ʧ��
**/						   
BOOL iot_os_set_system_datetime(                    
						T_AMOPENAT_SYSTEM_DATETIME* pDatetime
					   );
/** @}*/  


/**
 * @defgroup ���ӽӿں������� ���ӽӿں���
 * @{
 */
/**@example demo_alarm/src/demo_alarm.c
* alarm�ӿ�ʾ��
*/

/**���ӳ�ʼ���ӿ�
*@param		pConfig:		�������ò���
*@return	TURE: 			�ɹ�
*			FALSE: 		    ʧ��
**/
BOOL iot_os_init_alarm(                                      
                        T_AMOPENAT_ALARM_CONFIG *pConfig  
                   ); 

/**��������/ɾ���ӿ�
*@param		pAlarmSet:		�������ò���
*@return	TURE: 			�ɹ�
*			FALSE: 		    ʧ��
**/
BOOL iot_os_set_alarm(                                        
                        T_AMOPENAT_ALARM_PARAM *pAlarmSet    
                   );
/** @}*/ 


/**
 * @defgroup �ٽ���Դ�ӿں������� �ٽ���Դ�ӿں���
 * @{
 */
 
/**�����ٽ���Դ���ӿڣ��ر������ж�
*@return	HANDLE:    �����ٽ���Դ�������
**/
HANDLE iot_os_enter_critical_section(               
                        VOID
                                );

/**�˳��ٽ���Դ���ӿڣ������ж�
*@param		hSection:		�ٽ���Դ�����
**/
VOID iot_os_exit_critical_section(             
                        HANDLE hSection        
                             );
/** @}*/ 

/**
 * @defgroup �ٽ���Դ�ӿں������� �ٽ���Դ�ӿں���
 * @{
 */
 
/**�����ź����ӿ�
*@param		nInitCount:		�ź�������
*@return	HANDLE: 	    �����ź������
**/
HANDLE iot_os_create_semaphore(                     
                        UINT32 nInitCount       
                          );

/**ɾ���ź����ӿ�
*@param		hSem:		�ź������
*@return	TURE: 		�ɹ�
*			FALSE: 		ʧ��
**/
BOOL iot_os_delete_semaphore(                       
                        HANDLE hSem            
                        );

/**�ȴ��ź����ӿ�
*@param		hSem:		�ź������
*@param		nTimeOut:   �ȴ��ź�����ʱʱ�䣬if nTimeOut < 5ms, means forever
*@return	TURE: 		�ɹ�
*			FALSE: 		ʧ��
**/
BOOL iot_os_wait_semaphore(                        
                        HANDLE hSem,           
                        UINT32 nTimeOut         
                      );

/**�ͷ��ź����ӿ�
*@param		hSem:		�ź������
*@return	TURE: 		�ɹ�
*			FALSE: 		ʧ��
**/
BOOL iot_os_release_semaphore(
                        HANDLE hSem            
                         );

/**��ȡ������ֵ
*@param		hSem:		 �ź������
*@return	nInitCount:  �ź����ĸ���
**/
UINT32 iot_os_get_semaphore_value           
                        (
                        HANDLE hSem             
                        );
/** @}*/ 


/**
 * @defgroup �ڴ�ӿں������� �ڴ�ӿں���
 * @{
 */

/**�ڴ�����ӿ�malloc
*@param		nSize:		 ������ڴ��С
*@return	PVOID:       �ڴ�ָ��
**/
PVOID iot_os_malloc(                              
                        UINT32 nSize           
               );

/**�ڴ�����ӿ�realloc
*@param		pMemory:	     �ڴ�ָ�룬malloc�ӿڷ���ֵ
*@param		nSize:	     ������ڴ��С
*@return	PVOID:       �ڴ�ָ��
**/
PVOID iot_os_realloc(                               
                        PVOID pMemory,          
                        UINT32 nSize       
                );

/**�ڴ��ͷŽӿ�
*@param		pMemory:	     �ڴ�ָ�룬malloc�ӿڷ���ֵ
**/
VOID iot_os_free(                                  
                        PVOID pMemory     
            );
/** @}*/ 

/**
 * @defgroup �����ӿں������� �����ӿں���
 * @{
 */

/**ϵͳ˯�߽ӿ�
*@param		nMillisecondes:	     ˯��ʱ��
*@return	TURE: 		�ɹ�
*			FALSE: 		ʧ��
**/
BOOL iot_os_sleep(                              
                        UINT32 nMillisecondes   
             );

/**��ȡϵͳtick�ӿ�
*@return	tick_num:   ����ϵͳʱ��tickֵ
**/
UINT32 iot_os_get_system_tick(                    
                        VOID
                         );

/**��ȡ������ӿ�
*@return	rand_num:   ���������
**/
UINT32 iot_os_rand(                              
                        VOID
              );

/**������������ӽӿ�
*@param		seed:	     ���������
**/
VOID iot_os_srand(                                  
                        UINT32 seed            
             );

/**�ػ��ӿ�
**/
VOID iot_os_shut_down(                            
                        VOID
                 );

/**�����ӿ�
**/
VOID iot_os_restart(                              
                        VOID
               );

/**��Ƶ���ƽӿ�
*@param		freq:	     ��Ƶֵ
**/
VOID iot_os_sys_request_freq(                       
                        E_AMOPENAT_SYS_FREQ freq
               );

/** @}*/ 

/** @}*/  //ģ���β


#endif

