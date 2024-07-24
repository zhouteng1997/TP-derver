#include "pch.h"
#include "Çý¶¯½Ó¿Ú.h"
#include "hookapi.h"

typedef BOOL(WINAPI* CALL_ReadProcessMemory)(
	IN  HANDLE  hProcess,
	IN  LPCVOID lpBaseAddress,
	OUT LPVOID  lpBuffer,
	IN  SIZE_T  nSize,
	OUT SIZE_T* lpNumberOfBytesRead
);

CALL_ReadProcessMemory old_ReadProcessMemory = (CALL_ReadProcessMemory)ReadProcessMemory;

BOOL WINAPI r0_ReadProcessMemory(
	IN  HANDLE  hProcess,
	IN  LPCVOID lpBaseAddress,
	OUT LPVOID  lpBuffer,
	IN  SIZE_T  nSize,
	OUT SIZE_T* lpNumberOfBytesRead
) {
	if (!hProcess || hProcess == (HANDLE)-1)
	{
		return old_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
	return TROAPI::ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL HOOKReadProcessMemory(BOOL isHook) {
	if (isHook)
		hookapi((PVOID*)&old_ReadProcessMemory, r0_ReadProcessMemory);
	else
		unhookapi((PVOID*)&old_ReadProcessMemory, r0_ReadProcessMemory);
	return 1;
}