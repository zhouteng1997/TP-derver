#include"pch.h"
#include "�����ӿ�.h"

typedef BOOL(WINAPI* CALL_ReadProcessMemory)(
	[in]  HANDLE  hProcess,
	[in]  LPCVOID lpBaseAddress,
	[out] LPVOID  lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T* lpNumberOfBytesRead
	);

CALL_ReadProcessMemory old_ReadProcessMemory = (CALL_ReadProcessMemory)ReadProcessMemory;

BOOL WINAPI r0_ReadProcessMemory(
	[in]  HANDLE  hProcess,
	[in]  LPCVOID lpBaseAddress,
	[out] LPVOID  lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T* lpNumberOfBytesRead
) {
	if (!hProcess) return FALSE;
	if (hProcess == (HANDLE)-1) {//����ǵ�ǰ����,��ô����Դ����
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