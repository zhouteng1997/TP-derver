#include "pch.h"
#include "�����ӿ�.h"
#include "hookapi.h"
#include <cstdio>

typedef unsigned __int64 UINT_PTR, * PUINT_PTR;

//typedef BOOL(WINAPI* CALL_ZwQueryVirtualMemory)(
//	_In_		HANDLE                   ProcessHandle,
//	_In_opt_	PVOID                    BaseAddress,
//	_In_		MEMORY_INFORMATION_CLASS MemoryInformationClass,
//	_Out_		PVOID                    MemoryInformation,
//	_In_		SIZE_T                   MemoryInformationLength,
//	_Out_opt_	PSIZE_T                  ReturnLength
//	);

UINT_PTR old_ZwQueryVirtualMemory = 0;

void Init() {
	HMODULE hdll = GetModuleHandleA("ntdll.dll");
	if (hdll) {
		old_ZwQueryVirtualMemory = (UINT_PTR)GetProcAddress(hdll, "ZwQueryVirtualMemory");
	}
}


BOOL WINAPI r0_ZwQueryVirtualMemory(
	_In_		HANDLE                   ProcessHandle,
	_In_opt_	PVOID                    BaseAddress,
	_In_		MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_		PVOID                    MemoryInformation,
	_In_		SIZE_T                   MemoryInformationLength,
	_Out_opt_	PSIZE_T                  ReturnLength
)
{
	//if (!ProcessHandle || ProcessHandle == (HANDLE)-1)
	//{
	//	return old_ZwQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	//}
	//������Ч�Ľ��̶�д��������

	// ��ȡ��׼������
	FILE* file;
	freopen_s(&file, "CONOUT$", "w", stdout);
	// �����־
	printf("����r0_ZwQueryVirtualMemory\n");
	// �ر��ļ����
	fclose(file);
	return TROAPI::MyZwQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}

BOOL HOOKZwQueryVirtualMemory(BOOL isHook) {
	if (isHook)
		hookapi((PVOID*)&old_ZwQueryVirtualMemory, r0_ZwQueryVirtualMemory);
	else
		unhookapi((PVOID*)&old_ZwQueryVirtualMemory, r0_ZwQueryVirtualMemory);
	return 1;
}