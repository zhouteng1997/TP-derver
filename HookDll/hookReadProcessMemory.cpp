#include "pch.h"
#include "驱动接口.h"
#include "hookapi.h"
#include <cstdio>

typedef BOOL(WINAPI* CALL_ReadProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesRead
	);

CALL_ReadProcessMemory old_ReadProcessMemory = (CALL_ReadProcessMemory)ReadProcessMemory;

BOOL WINAPI r0_ReadProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesRead
) {
	if (!hProcess || hProcess == (HANDLE)-1)
	{
		return old_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
	//所有有效的进程读写都走驱动
	return TROAPI::MyReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL HOOKReadProcessMemory(BOOL isHook) {
	if (isHook)
		hookapi((PVOID*)&old_ReadProcessMemory, r0_ReadProcessMemory);
	else
		unhookapi((PVOID*)&old_ReadProcessMemory, r0_ReadProcessMemory);
	return 1;
}