#include "string.h"
#include "iot_debug.h"
#include "iot_gpio.h"
#include "iot_os.h"

#define alarm_print iot_debug_print

VOID demo_alarm_handle(T_AMOPENAT_ALARM_MESSAGE *pAlarmMessage)
{
    T_AMOPENAT_SYSTEM_DATETIME curTime;

    // 4. ����ʱ�䵽��
    if (pAlarmMessage->evtId == OPENAT_DRV_EVT_ALARM_IND)
    {
        alarm_print("[alarm] handle index = %x", pAlarmMessage->param.alarmIndex);

        iot_os_get_system_datetime(&curTime);

        alarm_print("[alarm] handle now %u:%u:%u %u:%u:%u", 
            curTime.nYear, curTime.nMonth, curTime.nDay,
            curTime.nHour, curTime.nMin, curTime.nSec);
    }
}


VOID demo_alarm_init(VOID)
{
    T_AMOPENAT_ALARM_CONFIG alarmCfg;
    T_AMOPENAT_ALARM_PARAM pAlarmSet;
    T_AMOPENAT_SYSTEM_DATETIME curTime;
    BOOL err;
    
    //1. ��ʼ������, �������ӻص�����
    alarmCfg.pAlarmMessageCallback = demo_alarm_handle;
    iot_os_init_alarm(&alarmCfg);

    //2. ��ȡ��ǰʱ��, 
    /*   ע:���û�е���iot_os_set_system_datetime�ӿ�����ʱ��,
    *       ��ʱ��Ĭ��Ϊ2012.6.1 10.0.0
    */
    iot_os_get_system_datetime(&curTime);
    alarm_print("[alarm] now %u:%u:%u %u:%u:%u", 
        curTime.nYear, curTime.nMonth, curTime.nDay,
        curTime.nHour, curTime.nMin, curTime.nSec);

    //3. ��������, 10s�󴥷����ӻص�
    /*ע:alarmRecurrent 1���ֽ�,  ��һλ��1��ʾ���ζ�ʱ, 1-7λ��ʾ�ܶ�ʱ, 
    *      ���ʶ�ʱ���ܶ�ʱ����ͬʱ����
    *      if (((alarmRecurrent & 0xfe) != 0)
    *             && ((pAlarm->nRecurrent & 0x1) != 0))
    *           return FALSE;
    */
    pAlarmSet.alarmIndex = 0; // ��ʱ������Χ(0-14)
    pAlarmSet.alarmOn = TRUE; // TURE����, FALSE ���
    pAlarmSet.alarmRecurrent = 1; // ����1���ζ�ʱ
    memcpy(&pAlarmSet.alarmTime, &curTime, sizeof(T_AMOPENAT_SYSTEM_DATETIME));
    pAlarmSet.alarmTime.nSec += 10; // ��������ʱ��
    err = iot_os_set_alarm(&pAlarmSet);

    if (!err)
        return;
    
    alarm_print("[alarm] set alarm %u:%u:%u %u:%u:%u", 
        pAlarmSet.alarmTime.nYear, pAlarmSet.alarmTime.nMonth, pAlarmSet.alarmTime.nDay,
        pAlarmSet.alarmTime.nHour, pAlarmSet.alarmTime.nMin, pAlarmSet.alarmTime.nSec);
}

VOID app_main(VOID)
{
    alarm_print("[alarm] app_main");

    demo_alarm_init();
}