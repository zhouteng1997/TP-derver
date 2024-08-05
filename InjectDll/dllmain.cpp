// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <shlwapi.h>
#include <tchar.h>
#include <stdio.h>

const TCHAR* GetCurrentProcessName(IN OUT TCHAR* exeName) {
	GetModuleFileName(NULL, exeName, MAX_PATH);
	PathStripPath(exeName);
	return exeName;
}

DWORD __stdcall WorkThread(LPVOID lpram) {


	TCHAR exeName[MAX_PATH];
	GetCurrentProcessName(exeName);

	char buf[1024];
	sprintf_s(buf, "Inject OK \n");
	OutputDebugStringA(buf);

	if (_tcsicmp(exeName, _T("win32calc.exe")) != 0)
	{
		LoadLibraryA("C:\\Users\\admin\\Desktop\\工具\\InjectDl.dll");
		MessageBox(NULL, exeName, _T("加载InjectDl.dll成功"), MB_ICONINFORMATION);
		return 0;
	}


	return 0;


	/*TCHAR exeName[MAX_PATH];
	GetCurrentProcessName(exeName);

	DWORD gamePid = GetGameProcessId();
	DWORD currentPid = GetCurrentProcessId();

	char buf[1024];
	sprintf_s(buf, "新进程创建：  当前pid为%d \n", currentPid);
	OutputDebugStringA(buf);


	if (_tcsicmp(exeName, _T("aaaaaa.exe")) == 0) {
		DWORD gamePid = GetGameProcessId();
		DWORD currentPid = GetCurrentProcessId();
		int num = 0;
		while (gamePid != currentPid && num++ < 30) {
			gamePid = GetGameProcessId();
			currentPid = GetCurrentProcessId();
			sprintf_s(buf, "比对： 当前pid为%d  游戏pid为%d \n", currentPid, gamePid);
			OutputDebugStringA(buf);
			Sleep(1000);
		}
		if (IsGameProcess()) {
			sprintf_s(buf, "加载DLL： 当前pid为%d \n", currentPid);
			OutputDebugStringA(buf);
			LoadLibraryA("c:\\game64.dll");
			MessageBox(0, exeName, _T("OK"), MB_OK);
		}
		return 0;
	}
	return 0;*/
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		HANDLE hTread = CreateThread(NULL, NULL, WorkThread, NULL, NULL, NULL);
		if (hTread) {
			CloseHandle(hTread);
		}
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

