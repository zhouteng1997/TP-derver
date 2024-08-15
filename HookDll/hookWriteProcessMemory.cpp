#include "pch.h"
#include "Çý¶¯½Ó¿Ú.h"
#include "hookapi.h"
#include <cstdio>

typedef BOOL(WINAPI* CALL_WriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	);

CALL_WriteProcessMemory old_WriteProcessMemory = (CALL_WriteProcessMemory)WriteProcessMemory;

BOOL WINAPI r0_WriteProcessMemory(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
) {
	if (!hProcess || hProcess == (HANDLE)-1)
	{
		return old_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}
	return TROAPI::MyWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL HOOKWriteProcessMemory(BOOL isHook) {
	if (isHook)
		hookapi((PVOID*)&old_WriteProcessMemory, r0_WriteProcessMemory);
	else
		unhookapi((PVOID*)&old_WriteProcessMemory, r0_WriteProcessMemory);
	return 1;
}