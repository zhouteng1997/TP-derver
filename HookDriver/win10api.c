#include "win10api.h"


//���̾��תPID
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
	//�л����̿ռ�
	KeStackAttachProcess((PRKPROCESS)pEProcess, &apc_state);
	//�����л��Ľ����У��鿴������
	status = ZwQueryInformationProcess(handle,
		ProcessBasicInformation,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL);
	//�����߳�
	KeUnstackDetachProcess(&apc_state);
	if (NT_SUCCESS(status))
	{
		return (HANDLE)pbi.UniqueProcessId;
	}
	return 0;
}