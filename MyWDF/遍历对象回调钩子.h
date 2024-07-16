#include <ntdef.h>


//遍历所有 进程 线程 注册的ObRegisterCallBacks回调
ULONG EnumObRegisterCallBacks(); 

//根据地址 判断所属驱动模块
BOOLEAN ObGetDriverNameByPoint(ULONG_PTR Point, OUT WCHAR* szDriverName);

//获取函数中的跳转地址
PVOID GetMovPoint(PVOID pCallPoint);

//获取PsLoadedModuleList地址，方便判断地址所属模块
PVOID GetPsLoadedListModule();