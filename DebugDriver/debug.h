#include <Ntifs.h>

//������һ����ת
VOID ModifyKdpTrap(PVOID myaddress, PVOID targetaddress);

//��ֹ��ȫ�������ʧ��
VOID DisableKdDebuggerEnabled();

//ժ��kdcom��eprocess
VOID HideDriver();

//��ת
VOID ModifyIoAllocateMdl(PVOID myaddress, PVOID targetaddress);

VOID UnHookKdpTrap();

VOID UnHookIoAllocateMdl();