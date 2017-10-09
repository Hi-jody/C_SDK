#include "string.h"
#include "iot_debug.h"
#include "iot_audio.h"

#define audio_print iot_debug_print
HANDLE g_demo_timer1;

/* ע: ÿ��20msһ֡, ��ͬ����Ƶ����һ֡���Ȳ�ͬ
    ��Ƶ����                            һ֡����
    OPENAT_REC_MODE_AMR475,             0x0000000D,
    OPENAT_REC_MODE_AMR515,             0x0000000E,
    OPENAT_REC_MODE_AMR59,              0x00000010,
    OPENAT_REC_MODE_AMR67,              0x00000012,
    OPENAT_REC_MODE_AMR74,              0x00000014,
    OPENAT_REC_MODE_AMR795,             0x00000015,
    OPENAT_REC_MODE_AMR102,             0x0000001B,
    OPENAT_REC_MODE_AMR122,             0x00000020,

    ÿ����¼�����ݵĴ�С = 1000(ms) / 20(ms) * ֡����
    ����OPENAT_REC_MODE_AMR795 ÿ�������ݴ�СΪ1000 / 20 * 21
*/
#define DEMO_RECORD_LENGTH 96000 
#define DEMO_RECORD_AMR_HEAD_BUFF "#!AMR\n"
#define DEMO_RECORD_AMR_HEAD_LEN 6
#define DEMO_RECODE_AMR_FRAME_LEN (21)
#define DEMO_RECORD_MODE OPENAT_REC_MODE_AMR795 
#define DEMO_RECORD_CH OPENAT_AUD_CHANNEL_LOUDSPEAKER
#define DEMO_CYCLE_BUFF_LEN (0X10000)
#define DEMO_TIMER_TIMEOUT (5000) // 5000ms

static UINT8  g_s_audio_rec_buff[DEMO_RECORD_LENGTH];
static UINT32 g_s_audio_rec_total_len = DEMO_RECORD_AMR_HEAD_LEN;
static UINT32 g_s_first_play_len = 0;
static UINT8 g_s_cycle_buff[DEMO_CYCLE_BUFF_LEN];

static E_AMOPENAT_PLAY_MODE demo_play_format_get(void)
{
    switch(DEMO_RECORD_MODE)
    {
        case OPENAT_REC_MODE_AMR475:
        case OPENAT_REC_MODE_AMR515:
        case OPENAT_REC_MODE_AMR59:
        case OPENAT_REC_MODE_AMR67:
        case OPENAT_REC_MODE_AMR74:
        case OPENAT_REC_MODE_AMR795:
        case OPENAT_REC_MODE_AMR102:
        case OPENAT_REC_MODE_AMR122:
        case OPENAT_REC_MODE_AMR_RING:
            return OPENAT_AUD_PLAY_MODE_AMR_RING;

        default:
            return OPENAT_AUD_PLAY_MODE_QTY; // ��������Ƶ��ʱ��֧��
    }
}

VOID demo_paly_handle(E_AMOPENAT_PLAY_ERROR result, int *len)
{
    /*
        1.ͨ��int *len;���жϲ����Ƿ����
            ���len������, ��ʾ���Ž���
            ���len����.����ͨ������*len��g_s_cycle_buff,������һ�����ŵ����ݵĳ��Ⱥ�����,
            ��*len����Ϊ0,��ʾ��һ������buffΪ��,����ֹ����
          ע:
             ��*len��g_s_cycle_buff��Ҫ����֡��������, ����demo����
    */
    static UINT32 total_len = 0;
    
    int frame_num = 1; // ��ӵ�g_s_cycle_buff�е�֡����

    if (total_len == 0)
    {
        total_len += g_s_first_play_len;
    }
   
    if (len)
    {
        if (total_len + DEMO_RECODE_AMR_FRAME_LEN > g_s_audio_rec_total_len)
        {
            //���ݲ��Ž�����*len����Ϊ0
            *len = 0;
            audio_print("[audio] demo_paly_handle data copy end %d", result);
            return;
        }
        // ��g_s_cycle_buff���������
        memcpy(g_s_cycle_buff, &g_s_audio_rec_buff[total_len], DEMO_RECODE_AMR_FRAME_LEN*frame_num);
        
        // ������ݵĳ���
        *len = DEMO_RECODE_AMR_FRAME_LEN*frame_num;
        total_len += *len;
        //audio_print("[audio] demo_paly_handle %x, %x, %x", total_len, g_s_audio_rec_total_len, g_s_audio_rec_buff[total_len]);
    }
    else
    {
        audio_print("[audio] demo_paly_handle play end %d", result);
    }
}

VOID demo_time_handle(T_AMOPENAT_TIMER_PARAMETER *pParameter)
{
    T_AMOPENAT_PLAY_PARAM playParam;
    BOOL err;

    //6. �ر�¼��
    err = iot_audio_rec_stop();
    audio_print("[audio] AUDREC stop BOOL %d", err);
    
    //7. ����¼��
    // ��һ�β��ŵĳ���, 
    g_s_first_play_len = DEMO_RECORD_AMR_HEAD_LEN + DEMO_RECODE_AMR_FRAME_LEN * 6;
    // ��һ�β��ŵ�����
    memcpy(g_s_cycle_buff, g_s_audio_rec_buff, g_s_first_play_len);
    
    playParam.playBuffer = TRUE;
    playParam.playBufferParam.callback = demo_paly_handle;
    playParam.playBufferParam.format = demo_play_format_get();
    playParam.playBufferParam.len = g_s_first_play_len;
    playParam.playBufferParam.pBuffer = g_s_cycle_buff;
    playParam.playBufferParam.loop = 0;
    err = iot_audio_play_music(&playParam);
    
    audio_print("[audio] AUDREC play BOOL %d", err);
}

VOID demo_audio_rec_handle(UINT8* data, UINT8 len)
{
    static BOOL init = FALSE; 

    //4. ����buff amr head
    if (!init)
    {
        memset(g_s_audio_rec_buff, 0, DEMO_RECORD_LENGTH);
        memcpy(g_s_audio_rec_buff, DEMO_RECORD_AMR_HEAD_BUFF, DEMO_RECORD_AMR_HEAD_LEN);
    }
    init = TRUE;

    if (DEMO_RECORD_LENGTH < g_s_audio_rec_total_len + len)
        return;
    //5. ����¼������, ÿ��һ֡
    memcpy(g_s_audio_rec_buff+g_s_audio_rec_total_len, data, len);
    g_s_audio_rec_total_len += len;
    
    //audio_print("[audio] AUDREC data total_len %x, %x", g_s_total_len, len);
}

VOID demo_audio_set_channel(VOID)
{
    // ����ͨ��
    switch(DEMO_RECORD_CH)
    {
        case OPENAT_AUD_CHANNEL_HANDSET:
            
            iot_audio_set_channel(OPENAT_AUD_CHANNEL_HANDSET);
            iot_audio_set_channel_with_same_mic(OPENAT_AUD_CHANNEL_HANDSET, OPENAT_AUD_CHANNEL_LOUDSPEAKER);
            break;

         case OPENAT_AUD_CHANNEL_LOUDSPEAKER:
         default:   
            iot_audio_set_channel(OPENAT_AUD_CHANNEL_LOUDSPEAKER);
            iot_audio_set_speaker_gain(OPENAT_AUD_SPK_GAIN_18dB);
            iot_audio_set_channel_with_same_mic(OPENAT_AUD_CHANNEL_HANDSET, OPENAT_AUD_CHANNEL_LOUDSPEAKER);
            break;   
    }

    audio_print("[audio] AUDREC channel %d", DEMO_RECORD_CH);
}


VOID demo_audRecStart(VOID)
{
    BOOL err = FALSE;

    //¼����ʽAMR795,
    err = iot_audio_rec_start(DEMO_RECORD_MODE, demo_audio_rec_handle);

    audio_print("[audio] AUDREC start BOOL %d", err);
}

VOID demo_audRecStopTimer(VOID)
{
    // ��ʱ5����ֹͣ¼��
    g_demo_timer1 = iot_os_create_timer(demo_time_handle, NULL);
    iot_os_start_timer(g_demo_timer1, DEMO_TIMER_TIMEOUT);
}


VOID demo_audio_init(VOID)
{
   
    // 1.����ͨ��������
    demo_audio_set_channel();

    //2.  ��ʼ¼��
    demo_audRecStart();

    //3. ���ö�ʱ�ر�¼��, ������¼��
    demo_audRecStopTimer();
}

VOID app_main(VOID)
{
    audio_print("[audio] app_main");

    demo_audio_init();
}
