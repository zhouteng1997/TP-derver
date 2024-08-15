#include <Ntifs.h>

//这里做一个跳转
VOID ModifyKdpTrap(PVOID myaddress, PVOID targetaddress);

//防止安全组件加载失败
VOID DisableKdDebuggerEnabled();

//摘掉kdcom的eprocess
VOID HideDriver();

//跳转
VOID ModifyIoAllocateMdl(PVOID myaddress, PVOID targetaddress);

VOID UnHookKdpTrap();

VOID UnHookIoAllocateMdl();