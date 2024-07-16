#include <wdm.h>

//初始化回调
BOOLEAN ObRegisterCallBacksInit(PDRIVER_OBJECT pDriverObject);
//卸载回调
void ObRegisterUnload();
//判断是不是保护进程
BOOLEAN IsMyProcess();  // 判断是否是可以过保护的进程
//第一个回调
OB_PREOP_CALLBACK_STATUS First_CallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);
//最后一个回调
OB_PREOP_CALLBACK_STATUS Last_CallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation);