// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "驱动接口.h"
#include "hookapi.h"

BOOL HOOKReadProcessMemory(BOOL isHook);
// DLL 主入口函数
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//初始化临界区
		InitializeCriticalSection(&cs);
		MessageBoxA(NULL, "HookDll加载成功", "提示", MB_OK);
		if (TROAPI::OpenDevice() == HANDLE(-1))
			MessageBoxA(NULL, "驱动未加载", "提示", MB_OK);
		//hook
		HOOKReadProcessMemory(TRUE);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		//清理hook
		HOOKReadProcessMemory(FALSE);
		//删除临界区
		DeleteCriticalSection(&cs);
		break;
	}
	return TRUE;
}
