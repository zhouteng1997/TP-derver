// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>

// 获取函数地址
FARPROC GetFunctionAddress(const char* pszFunctionName)
{
    HMODULE hDll = ::LoadLibraryA("C:\\Windows\\System32\\VERSION.dll");
    if (hDll == NULL) {
        return NULL;
    }
    FARPROC pAddr = ::GetProcAddress(hDll, pszFunctionName);
    ::FreeLibrary(hDll);
    return pAddr;
}

// 定义函数的调用方式
#define DEFINE_FUNCTION(apiName, internalName) \
    extern "C" void internalName() \
    { \
        FARPROC fp = GetFunctionAddress(apiName); \
        if (fp != NULL) \
        { \
            auto func = reinterpret_cast<void(*)(void)>(fp); \
            func(); \
        } \
    }

// 使用宏来定义实际的函数
DEFINE_FUNCTION("GetFileVersionInfoA", My_GetFileVersionInfoA)
DEFINE_FUNCTION("GetFileVersionInfoByHandle", My_GetFileVersionInfoByHandle)
DEFINE_FUNCTION("GetFileVersionInfoExA", My_GetFileVersionInfoExA)
DEFINE_FUNCTION("GetFileVersionInfoExW", My_GetFileVersionInfoExW)
DEFINE_FUNCTION("GetFileVersionInfoSizeA", My_GetFileVersionInfoSizeA)
DEFINE_FUNCTION("GetFileVersionInfoSizeExA", My_GetFileVersionInfoSizeExA)
DEFINE_FUNCTION("GetFileVersionInfoSizeExW", My_GetFileVersionInfoSizeExW)
DEFINE_FUNCTION("GetFileVersionInfoSizeW", My_GetFileVersionInfoSizeW)
DEFINE_FUNCTION("GetFileVersionInfoW", My_GetFileVersionInfoW)
DEFINE_FUNCTION("VerFindFileA", My_VerFindFileA)
DEFINE_FUNCTION("VerFindFileW", My_VerFindFileW)
DEFINE_FUNCTION("VerInstallFileA", My_VerInstallFileA)
DEFINE_FUNCTION("VerInstallFileW", My_VerInstallFileW)
DEFINE_FUNCTION("VerLanguageNameA", My_VerLanguageNameA)
DEFINE_FUNCTION("VerLanguageNameW", My_VerLanguageNameW)
DEFINE_FUNCTION("VerQueryValueA", My_VerQueryValueA)
DEFINE_FUNCTION("VerQueryValueW", My_VerQueryValueW)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ::LoadLibraryA("C:\\Windows\\System32\\VERSION.dll");
        ::MessageBoxA(NULL, "DLL加载成功!", "Success", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
