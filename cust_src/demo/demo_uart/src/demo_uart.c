#include "string.h"
#include "iot_debug.h"
#include "iot_uart.h"

#define uart_print iot_debug_print
#define DEMO_UART_PORT1 OPENAT_UART_1
#define DEMO_UART_PORT2 OPENAT_UART_2
#define DEMO_UART_RECV_TIMEOUT (5 * 1000) // 2S

//�жϷ�ʽ������1����
//ע: �ж����и��ӵ��߼�,Ҫ������Ϣ��task�д���
void uart_recv_handle(T_AMOPENAT_UART_MESSAGE* evt)
{
    INT8 recv_buff[64] = {0};
    int32 recv_len;
    int32 dataLen = evt->param.dataLen;

    switch(evt->evtId)
    {
        case OPENAT_DRV_EVT_UART_RX_DATA_IND:
    
            recv_len = iot_uart_read(DEMO_UART_PORT1, recv_buff, dataLen , DEMO_UART_RECV_TIMEOUT);

            uart_print("[uart] uart1 OPENAT_DRV_EVT_UART_RX_DATA_IND");
            uart_print("[uart] uart1 recv_len %d, recv_buff %s", recv_len, recv_buff);

            break;

        case OPENAT_DRV_EVT_UART_TX_DONE_IND:
            uart_print("[uart] uart1 OPENAT_DRV_EVT_UART_TX_DONE_IND");
            break;
        default:
            break;
    }
}

VOID demo_uart_read(VOID)
{
    char read_buff[64];
    INT32 read_len;
    
    read_len = iot_uart_read(DEMO_UART_PORT2, read_buff, sizeof(read_buff), DEMO_UART_RECV_TIMEOUT);

    if (read_len <= 0)
        uart_print("[uart] uart2 read timeout");
    else 
        uart_print("[uart] uart2 read_len %d, read_buff %s", read_len, read_buff);
}

VOID demo_uart_write(VOID)
{
    char *write_buff1 = "uart1 hello world";
    char *write_buff2 = "uart2 hello world";
    int32 write_len;
    
    write_len = iot_uart_write(DEMO_UART_PORT1, write_buff1, strlen(write_buff1));
    uart_print("[uart] uart1 write_len %d, write_buff %s", write_len, write_buff1);

    write_len = iot_uart_write(DEMO_UART_PORT2, write_buff2, strlen(write_buff2));
    uart_print("[uart] uart2 write_len %d, write_buff %s", write_len, write_buff2);
}

VOID demo_uart_open(VOID)
{
    BOOL err;
    T_AMOPENAT_UART_PARAM uartCfg;
    
    memset(&uartCfg, 0, sizeof(T_AMOPENAT_UART_PARAM));
    uartCfg.baud = OPENAT_UART_BAUD_115200; //������
    uartCfg.dataBits = 8;   //����λ
    uartCfg.stopBits = 1; // ֹͣλ
    uartCfg.parity = OPENAT_UART_NO_PARITY; // ��У��
    uartCfg.flowControl = OPENAT_UART_FLOWCONTROL_NONE; //������
    uartCfg.txDoneReport = TRUE; // ����TURE�����ڻص��������յ�OPENAT_DRV_EVT_UART_TX_DONE_IND
    uartCfg.uartMsgHande = uart_recv_handle; //�ص�����

    // ����uart1 ʹ���жϷ�ʽ������
    err = iot_uart_config(DEMO_UART_PORT1, &uartCfg);
    uart_print("[uart] DEMO_UART_PORT1 open err %d", err);

    uartCfg.txDoneReport = FALSE; 
    uartCfg.uartMsgHande = NULL;
    // ����uart2 ʹ����ѵ��ʽ������
    err = iot_uart_config(DEMO_UART_PORT2, &uartCfg);
    uart_print("[uart] DEMO_UART_PORT1 open err %d", err);
}

VOID demo_uart_close(VOID)
{
    iot_uart_close(DEMO_UART_PORT1);
    iot_uart_close(DEMO_UART_PORT2);
    uart_print("[uart] close");
}

VOID demo_uart_init(VOID)
{   
    demo_uart_open(); // �򿪴���1�ʹ���2 (����1�жϷ�ʽ������, ����2��ѵ��ʽ������)
    demo_uart_write(); // �򴮿�1�ʹ���2 д����

    while(1)
    {
        demo_uart_read(); // ��ѵ��ʽ��ȡ����2����
    }
}

VOID app_main(VOID)
{
    uart_print("[uart] app_main");

    demo_uart_init();
}