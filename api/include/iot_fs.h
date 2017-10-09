#ifndef __IOT_FS_H__
#define __IOT_FS_H__

#include "iot_os.h"


/**
 * @defgroup iot_sdk_fs �ļ�ϵͳ�ӿ�
 * @{
 */
	/**@example demo_fs/src/demo_fs.c
	* fs�ӿ�ʾ��
	*/ 

/**���ļ�
*@param		pszFileNameUniLe:		�ļ�ȫ·������
*@param		iFlag:		�򿪱�־��ϸ��μ�E_AMOPENAT_FILE_OPEN_FLAG
*@return	INT32: 	    �����ļ����
**/
INT32 iot_fs_open_file(                           
                        WCHAR* pszFileNameUniLe,
                        UINT32 iFlag         
                  );

/**�ر��ļ�
*@param		iFd:		�ļ������open_file �� create_file ���ص�
*@return	INT32: 	    ����ֵС��0ʧ��, ����ɹ�
**/
INT32 iot_fs_close_file(                     
                        INT32 iFd           
                   );

/**��ȡ�ļ�
*@param		iFd:		�ļ������open_file �� create_file ���ص�
*@param		pBuf:		���ݱ���ָ��
*@param		iLen:		buf����
*@return	INT32: 	    ���ض�ȡ����, С��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_read_file(                            
                        INT32 iFd,            
                        UINT8 *pBuf,            
                        UINT32 iLen            
                  );

/**д���ļ�
*@param		iFd:		�ļ������open_file �� create_file ���ص�
*@param		pBuf:		��Ҫд�������ָ��
*@param		iLen:		���ݳ���
*@return	INT32: 	    ����д�볤��, С��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_write_file(                           
                        INT32 iFd,            
                        UINT8 *pBuf,          
                        UINT32 iLen             
                   );

/**����д��flash
*@param		iFd:		�ļ������open_file �� create_file ���ص�
*@return	INT32: 	    ��������д�볤��, С��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_flush_file(                           
                        INT32 iFd              
                   );    

/**�ļ���λ
*@note  ����iOffset�ĺ���ȡ����iOrigin��ֵ.
*@param		iFd:		�ļ������open_file �� create_file ���ص�
*@param		iOffset:	ƫ����
*@param		iOrigin:	������ϸ��μ�E_AMOPENAT_FILE_SEEK_FLAG
*@return	INT32: 	    �����ļ���ƫ����
**/
INT32 iot_fs_seek_file(                           
                        INT32 iFd,            
                        INT32 iOffset,         
                        UINT8 iOrigin          
                  );

/**�����ļ�
*@param		pszFileNameUniLe:	�ļ�ȫ·������
*@return	INT32: 	            �����ļ����, С��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_create_file(                          
                        WCHAR* pszFileNameUniLe   
                    );

/**ɾ���ļ�
*@param		pszFileNameUniLe:	�ļ�ȫ·������
*@return	INT32: 	            ����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_delete_file(                          
                        WCHAR* pszFileNameUniLe
                    );

/**�ı��ļ���С
*@param		iFd:	�ļ����
*@param		uSize:	���ô�С
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_change_size(
                    INT32 iFd,
                    UINT32 uSize
                );

/**�л���ǰ����Ŀ¼
*@param		pszDirNameUniLe:	Ŀ¼·��
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_change_dir(                            
                        WCHAR* pszDirNameUniLe  
                   );

/**����Ŀ¼
*@param		pszDirNameUniLe:	Ŀ¼·��
*@param		iMode:	            Ŀ¼���ԣ���ϸ��μ�E_AMOPENAT_FILE_ATTR_TAG
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_make_dir(                              
                        WCHAR* pszDirNameUniLe, 
                        UINT32 iMode          
                 );

/**ɾ��Ŀ¼
*@param		pszDirNameUniLe:	Ŀ¼·��,��Ŀ¼����Ϊ�գ��ӿڲ��ܷ��سɹ�
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_remove_dir(                          
                        WCHAR* pszDirNameUniLe  
                   );

/**�ݹ�ɾ��Ŀ¼
*@param		pszDirNameUniLe:	Ŀ¼·��,��Ŀ¼�������ļ���Ŀ¼���ᱻɾ�� 
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_remove_dir_rec(                        
                        WCHAR* pszDirNameUniLe 
                       );

/**��ȡ��ǰ·��
*@param		pCurDirUniLe:	Ŀ¼·��
*@param		uUnicodeSize:	    �洢Ŀ¼��Ϣ�ռ��С
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_get_current_dir(                    
                        WCHAR* pCurDirUniLe,   
                        UINT32 uUnicodeSize   
                        );

/**�����ļ�
*@param		pszFileNameUniLe:	Ŀ¼·��
*@param		pFindData:	        ���ҽ������
*@return	INT32: 	            �����ļ����,С��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_find_first_file(                     
                        WCHAR* pszFileNameUniLe,
                        PAMOPENAT_FS_FIND_DATA  pFindData
                        );

/**���������ļ�
*@param		iFd:	            �����ļ����
*@param		pFindData:	        ���ҽ������
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_find_next_file(                      
                        INT32 iFd,             
                        PAMOPENAT_FS_FIND_DATA  pFindData 
                       );

/**���ҽ���
*@param		iFd:	            �����ļ����
*@return	INT32: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_find_close(                            
                        INT32 iFd            
                   );

/**��ȡ�ļ�ϵͳ��Ϣ
*@param		devName:	�����ļ����
*@return	fileInfo: 	����ֵС��0��ʾʧ��,����ɹ�
**/
INT32 iot_fs_get_fs_info(                         
                        E_AMOPENAT_FILE_DEVICE_NAME       devName,         
                        T_AMOPENAT_FILE_INFO               *fileInfo                 
                   );

/** @}*/

#endif
