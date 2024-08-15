#include "pch.h"
#include "Çý¶¯½Ó¿Ú.h"
#include "hookapi.h"
#include <cstdio>

typedef BOOL(WINAPI* CALL_TerminateProcess)(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode
	);

CALL_TerminateProcess old_TerminateProcess = (CALL_TerminateProcess)TerminateProcess;

BOOL WINAPI r0_TerminateProcess(
	_In_ HANDLE hProcess,
	_In_ UINT uExitCode
) {
	if (!hProcess || hProcess == (HANDLE)-1)
	{
		return old_TerminateProcess(hProcess, uExitCode);
	}
	return TROAPI::MyTerminateProcess(hProcess, uExitCode);
}

BOOL HOOKTerminateProcess(BOOL isHook) {
	if (isHook)
		hookapi((PVOID*)&old_TerminateProcess, r0_TerminateProcess);
	else
		unhookapi((PVOID*)&old_TerminateProcess, r0_TerminateProcess);
	return 1;
}