#include "pch.h"
#include "hookapi.h"

// 临界区对象用于线程同步
CRITICAL_SECTION cs;

BOOL ModifyMemoryProtection(PVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtect(address, size, newProtect, oldProtect);
}

void hookapi(PVOID* ppOriginal, PVOID pHook) {
    EnterCriticalSection(&cs);
    try {
        DWORD oldProtect;

        // 修改原始函数地址的内存保护，以便我们可以写入
        if (ModifyMemoryProtection(ppOriginal, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // 将原始函数指针替换为我们的Hook函数指针
            *ppOriginal = pHook;
            // 恢复内存保护
            ModifyMemoryProtection(ppOriginal, sizeof(PVOID), oldProtect, &oldProtect);
        }
        else {
            std::cerr << "Failed to modify memory protection." << std::endl;
        }
    }
    catch (...) {
        std::cerr << "An exception occurred in hookapi." << std::endl;
    }
    LeaveCriticalSection(&cs);
}

void unhookapi(PVOID* ppOriginal, PVOID pHook) {
    EnterCriticalSection(&cs);
    try {
        DWORD oldProtect;

        // 修改原始函数地址的内存保护，以便我们可以写入
        if (ModifyMemoryProtection(ppOriginal, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // 将Hook函数指针恢复为原始函数指针
            *ppOriginal = pHook;
            // 恢复内存保护
            ModifyMemoryProtection(ppOriginal, sizeof(PVOID), oldProtect, &oldProtect);
        }
        else {
            std::cerr << "Failed to modify memory protection." << std::endl;
        }
    }
    catch (...) {
        std::cerr << "An exception occurred in unhookapi." << std::endl;
    }
    LeaveCriticalSection(&cs);
}