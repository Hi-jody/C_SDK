#include "iot_flash.h"

extern char _am_openat_ro_lma;
extern char _am_openat_ro_size;
extern char _am_openat_rw_lma;
extern char _am_openat_rw_size;


/**��ȡflash���õĵ�ַ�ռ䣬���صĵ�ַ��������iot_flash_erase\iot_flash_write\iot_flash_read�Ƚӿڡ�
*@param		addrout[out]:	���ؿ���flash��ַ
*@param		lenout[out]:	���ؿ���flash���ȣ���λΪ�ֽ�
*@return	E_AMOPENAT_MEMD_ERR: 	�ɹ�:OPENAT_MEMD_ERR_NO, ����ʧ��
*@note      �ýӿڷ��صĵ�ַ��64KB���롣���صĵ�ַ�ռ���ݵ�ǰ�����С��ȷ����
**/
VOID iot_flash_getaddr(    
                    UINT32* addrout,
                    UINT32* lenout
               )
{
    UINT32 appROEndAddr, appRWEndAddr;
	UINT32 appSize;
    if(addrout)
	{
		appROEndAddr = (UINT32)(&_am_openat_ro_lma + (UINT32)&_am_openat_ro_size);
		appRWEndAddr = (UINT32)(&_am_openat_rw_lma + (UINT32)&_am_openat_rw_size);
		*addrout = (appROEndAddr > appRWEndAddr) ? appROEndAddr : appRWEndAddr;
		*addrout = (UINT32)(((UINT32)(*addrout) + 0x10000 - 1)&(~0xffff));
	}
	if(lenout)
	{
		appSize = (UINT32)&_am_openat_ro_size + (UINT32)&_am_openat_rw_size;
		appSize = (appSize + 0X10000 - 1) & (~0xffff);
		*lenout = AM_OPENAT_ROM_SIZE - appSize;
	}
}

/**flash�� 
*@param		startAddr:		��д��ַ 64K����
*@param		endAddr:		��д������ַ
*@return	E_AMOPENAT_MEMD_ERR: 	�ɹ�:OPENAT_MEMD_ERR_NO, ����ʧ��
**/
E_AMOPENAT_MEMD_ERR iot_flash_erase(             
                        UINT32 startAddr,
                        UINT32 endAddr
                   )
{
    return IVTBL(flash_erase)(startAddr, endAddr);
}

/**flashд 
*@param		startAddr:		д��ַ 
*@param		size:		    д���ݴ�С
*@param		writenSize:		д�������ʹ�С
*@param		buf:		    д����ָ��
*@return	E_AMOPENAT_MEMD_ERR: 	�ɹ�:OPENAT_MEMD_ERR_NO, ����ʧ��
**/
E_AMOPENAT_MEMD_ERR iot_flash_write(             
                        UINT32 startAddr,
                        UINT32 size,
                        UINT32* writenSize,
                        CONST UINT8* buf
                   )
{
    return IVTBL(flash_write)(startAddr, size, writenSize, buf);
}

/**flash��
*@param		startAddr:		����ַ 
*@param		size:		    �����ݴ�С
*@param		readSize:		���������ʹ�С
*@param		buf:		    ������ָ��
*@return	E_AMOPENAT_MEMD_ERR: 	�ɹ�:OPENAT_MEMD_ERR_NO, ����ʧ��
**/
E_AMOPENAT_MEMD_ERR iot_flash_read(               
                        UINT32 startAddr,
                        UINT32 size,
                        UINT32* readSize,
                        UINT8* buf
                   )
{
    return IVTBL(flash_read)(startAddr, size, readSize, buf);
}

