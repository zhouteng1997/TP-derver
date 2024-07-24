#include "pch.h"
#include "hookapi.h"

// �ٽ������������߳�ͬ��
CRITICAL_SECTION cs;

BOOL ModifyMemoryProtection(PVOID address, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtect(address, size, newProtect, oldProtect);
}

void hookapi(PVOID* ppOriginal, PVOID pHook) {
    EnterCriticalSection(&cs);
    try {
        DWORD oldProtect;

        // �޸�ԭʼ������ַ���ڴ汣�����Ա����ǿ���д��
        if (ModifyMemoryProtection(ppOriginal, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // ��ԭʼ����ָ���滻Ϊ���ǵ�Hook����ָ��
            *ppOriginal = pHook;
            // �ָ��ڴ汣��
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

        // �޸�ԭʼ������ַ���ڴ汣�����Ա����ǿ���д��
        if (ModifyMemoryProtection(ppOriginal, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // ��Hook����ָ��ָ�Ϊԭʼ����ָ��
            *ppOriginal = pHook;
            // �ָ��ڴ汣��
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