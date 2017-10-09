#ifndef __IOT_AUDIO_H__
#define __IOT_AUDIO_H__

#include "iot_os.h"


/**
 * @defgroup iot_sdk_audio ��Ƶ�ӿ�
 * @{
 */
/**@example demo_audio/src/demo_audio.c
* audio�ӿ�ʾ��
*/

/**������
*@note  ��ͨ����ʼʱ����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_open_tch(                                        
                        VOID
                );

/**�ر�����
*@note  ͨ������ʱ����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_close_tch(                                      
                        VOID
                 );

/**����TONE��
*@param  toneType:      TONE������
*@param  duration:      ����ʱ��
*@param  volume:        ��������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_play_tone(                                        
                        E_AMOPENAT_TONE_TYPE toneType,     
                        UINT16 duration,                   
                        E_AMOPENAT_SPEAKER_GAIN volume     
                 );

/**ֹͣ����TONE��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_stop_tone(                                        
                        VOID
                 );


/**����DTMF��
*@param  dtmfType:      DTMF����
*@param  duration:      ����ʱ��
*@param  volume:        ��������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_play_dtmf(                                        
                        E_AMOPENAT_DTMF_TYPE dtmfType,     
                        UINT16 duration,                   
                        E_AMOPENAT_SPEAKER_GAIN volume     
                 );

/**ֹͣ����DTMF��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_stop_dtmf(                            
                        VOID
                 );

/**������Ƶ
*@param  playParam:     ���Ų���
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_play_music(T_AMOPENAT_PLAY_PARAM*  playParam);

/**ֹͣ��Ƶ����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_stop_music(                                        
                        VOID
                  );

/**��ͣ��Ƶ����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_pause_music(                                     
                        VOID
                   );

/**�ָ���Ƶ����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_resume_music(                                       
                        VOID
                    );

/**����MP3������Ч
*@param  setEQ:        ����MP3��Ч
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_set_eq(                              
                        E_AMOPENAT_AUDIO_SET_EQ setEQ
                    );

/**����MIC
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_open_mic(                                    
                        VOID
                );

/**�ر�MIC
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_close_mic(                                         
                        VOID
                 );

/**����MIC����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_mute_mic(                                          
                        VOID
                );

/**���MIC����
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_unmute_mic(                                  
                        VOID
                  );

/**����MIC������
*@note  micGainֵ���Ϊ20
*@param  micGain:       ����MIC������ֵ
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_set_mic_gain(                              
                        UINT16 micGain                 
                    );

/**��������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_open_speaker(                    
                        VOID
                    );

/**�ر�������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_close_speaker(                       
                        VOID
                     );


/**��������������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_mute_speaker(                                     
                        VOID
                    );

/**�������������
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_unmute_speaker(                                   
                        VOID
                      );

/**����������������
*@param     speakerGain:   ��������������ֵ
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_set_speaker_gain(                                  
                        E_AMOPENAT_SPEAKER_GAIN speakerGain 
                        );

/**��ȡ������������ֵ
*@return	E_AMOPENAT_SPEAKER_GAIN: 	 ����������������ֵ
**/
E_AMOPENAT_SPEAKER_GAIN iot_audio_get_speaker_gain(              
                        VOID
                                           );

/**������Ƶͨ��
*@param     channel:    ͨ��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_set_channel(                                       
                        E_AMOPENAT_AUDIO_CHANNEL channel    
                   );

/**���ù���ͬһ��MIC��Ƶͨ��
*@param     channel_1:    ͨ��1
*@param     channel_2:    ͨ��2
**/
VOID iot_audio_set_channel_with_same_mic(                          
                    E_AMOPENAT_AUDIO_CHANNEL channel_1,    
                    E_AMOPENAT_AUDIO_CHANNEL channel_2      
               );

/**����MIC��Ƶͨ������
*@param     hfChanne:    �ֱ�ͨ��
*@param     erChanne:    ����ͨ��
*@param     ldChanne:    ����ͨ��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_set_hw_channel(
                      E_AMOPENAT_AUDIO_CHANNEL hfChanne,    
                      E_AMOPENAT_AUDIO_CHANNEL erChanne,    
                      E_AMOPENAT_AUDIO_CHANNEL ldChanne    
                     );

/**��ȡ��ǰͨ��
*@return	E_AMOPENAT_AUDIO_CHANNEL: 	  ����ͨ��ֵ
**/
E_AMOPENAT_AUDIO_CHANNEL iot_audio_get_current_channel(            
                        VOID
                                               );

/**��ʼ¼��
*@note ¼����ʱֻ֧��amr��ʽ
*@param     codec:                  ¼����ʽ
*@param     AUDIO_REC_CALLBACK:     ��ȡ¼�����ݻص�
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_rec_start(
                    OPENAT_REC_MODE_T codec,
                            AUDIO_REC_CALLBACK recHanlder);

/**ֹͣ¼��
*@return	TRUE: 	    �ɹ�
*           FALSE:      ʧ��
**/
BOOL iot_audio_rec_stop(VOID);

/** @}*/


#endif
