#include "win10api.h"


//进程句柄转PID
HANDLE HandleToPid(IN HANDLE ProcessID, IN HANDLE handle)
{
	KAPC_STATE apc_state;
	PEPROCESS pEProcess = 0;
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi = { 0 };

	RtlZeroMemory(&apc_state, sizeof(KAPC_STATE));
	status = PsLookupProcessByProcessId(ProcessID, &pEProcess);
	if (!NT_SUCCESS(status))
		return 0;
	//切换进程空间
	KeStackAttachProcess((PRKPROCESS)pEProcess, &apc_state);
	//在已切换的进程中，查看这个句柄
	status = ZwQueryInformationProcess(handle,
		ProcessBasicInformation,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL);
	//分离线程
	KeUnstackDetachProcess(&apc_state);
	if (NT_SUCCESS(status))
	{
		return (HANDLE)pbi.UniqueProcessId;
	}
	return 0;
}