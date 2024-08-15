#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI* NtQuerySystemInformationPtr)(
    int SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

bool IsTestModeEnabled() {
    // 获取 kernel32.dll 模块句柄
    HMODULE hNtDll = GetModuleHandle(TEXT("ntdll.dll"));
    if (!hNtDll) {
        std::cerr << "无法获取 nt.dll 模块句柄" << std::endl;
        return false;
    }

    // 获取 NtQuerySystemInformation 函数指针
    NtQuerySystemInformationPtr NtQuerySystemInformation =
        (NtQuerySystemInformationPtr)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        std::cerr << "无法获取 NtQuerySystemInformation 函数指针" << std::endl;
        return false;
    }

    typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    } SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

    SYSTEM_CODEINTEGRITY_INFORMATION integrityInfo = { 0 };
    integrityInfo.Length = sizeof(integrityInfo);

    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)103, // SystemCodeIntegrityInformation
        &integrityInfo,
        sizeof(integrityInfo),
        nullptr);

    if (status == STATUS_SUCCESS) {
        // 检查 CodeIntegrityOptions 的 0x02 标志
        return (integrityInfo.CodeIntegrityOptions & 0x02) != 0;
    }

    return false;
}

int main() {
    if (IsTestModeEnabled()) {
        std::cout << "系统处于测试模式。" << std::endl;
    }
    else {
        std::cout << "系统未处于测试模式。" << std::endl;
    }
    system("pause");
    return 0;
}
