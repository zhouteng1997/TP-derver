#include <wdm.h>

//��ʼ���ص�
BOOLEAN ObRegisterCallBacksInit(PDRIVER_OBJECT pDriverObject);
//ж�ػص�
void ObRegisterUnload();
//�ж��ǲ��Ǳ�������
BOOLEAN IsMyProcess();  // �ж��Ƿ��ǿ��Թ������Ľ���
//��һ���ص�
OB_PREOP_CALLBACK_STATUS First_CallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);
//���һ���ص�
OB_PREOP_CALLBACK_STATUS Last_CallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);