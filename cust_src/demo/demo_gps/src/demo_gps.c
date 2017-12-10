#include "string.h"
#include "iot_debug.h"
#include "iot_uart.h"

static void demo_gps_task(PVOID pParameter)
{
    char read_buff[1024];
    INT32 read_len;
	iot_pmd_poweron_ldo(OPENAT_LDO_POWER_CAM, 7);
	IVTBL(sys32k_clk_out)(1);
	while (1)
	{
		read_len = iot_uart_read(OPENAT_UART_2, read_buff, sizeof(read_buff), 100);
		if (read_len <= 0)
		{

		}
		else
		{
			read_buff[read_len] = 0;
			iot_debug_print("%s", read_buff);
		}
	}

}
VOID app_main(VOID)
{
    BOOL err;
    T_AMOPENAT_UART_PARAM uartCfg;

    memset(&uartCfg, 0, sizeof(T_AMOPENAT_UART_PARAM));
    uartCfg.baud = OPENAT_UART_BAUD_115200; //波特率
    uartCfg.dataBits = 8;   //数据位
    uartCfg.stopBits = 1; // 停止位
    uartCfg.parity = OPENAT_UART_NO_PARITY; // 无校验
    uartCfg.flowControl = OPENAT_UART_FLOWCONTROL_NONE; //无流控
    uartCfg.txDoneReport = FALSE;
    uartCfg.uartMsgHande = NULL;

    // 配置uart1 使用中断方式读数据
    err = iot_uart_config(OPENAT_UART_2, &uartCfg);

    iot_os_create_task(demo_gps_task,
                        NULL,
                        4096,
                        5,
                        OPENAT_OS_CREATE_DEFAULT,
                        "demo_gps");
}
