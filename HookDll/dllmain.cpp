// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "驱动接口.h"
#include "hookapi.h"
#include <stdio.h>


//WriteProcessMemory 写内存
//ReadProcessMemory 读内存
//TerminateProcess 结束进程
//VirtualProtectEx 修改页面属性
//VirtualAllocEx
//VirtualFreeEx
//CreateRemoteThread 调用call
//DuplicateHandle 复制句柄



BOOL HOOKReadProcessMemory(BOOL isHook);
BOOL HOOKZwQueryVirtualMemory(BOOL isHook);

// DLL 主入口函数
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		// 分配控制台
		AllocConsole();

		//// 获取标准输出句柄
		//FILE* file;
		//freopen_s(&file, "CONOUT$", "w", stdout);
		//// 输出日志
		//printf("DLL Loaded: Logging to console\n");
		//// 关闭文件句柄
		//fclose(file);

		MessageBoxA(NULL, "HookDll加载成功", "提示", MB_OK);
		//打开设备
		if (TROAPI::OpenDevice() == HANDLE(-1))
			MessageBoxA(NULL, "驱动未加载", "提示", MB_OK);
		//hook
		HOOKReadProcessMemory(TRUE);
		//HOOKZwQueryVirtualMemory(TRUE);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		//清理hook
		HOOKReadProcessMemory(FALSE);
		//HOOKZwQueryVirtualMemory(FALSE);
		//关闭设备
		TROAPI::CloseDevice();
		break;
	}
	return TRUE;
}
