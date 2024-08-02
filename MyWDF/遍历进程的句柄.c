#include<ntifs.h>
#include "win10�ṹ��.h"



//windows��������
UINT_PTR ObGetObjectType(PVOID object);

NTSTATUS ZwQueryInformationProcess(
	IN HANDLE ProcessHandle, // ���̾��
	IN PROCESSINFOCLASS InformationClass, // ��Ϣ����
	OUT PVOID ProcessInformation, // ����ָ��
	IN ULONG ProcessInformationLength, // ���ֽ�Ϊ��λ�Ļ����С
	OUT PULONG ReturnLength OPTIONAL // д�뻺����ֽ���
);

//typedef PHANDLE_TABLE_ENTRY(*PExpLookupHandleTableEntry)(
//	IN PHANDLE_TABLE HandleTable,//����1�Ǿ����ĵ�ַ���� HandleTable��ע�⣬���� HandleTable �ĵ�λ������Ҫ��������Ҫ�жϾ����ṹ��
//	IN EXHANDLE handle//����2�Ǿ��ֵ��PID ��ֵ����һ�����ֵ������ 0perproces ��һ�����̵õ���Ҳ�Ǿ��ֵ��ǰ����������ȫ�־�������������������̵ľ�±�
//	);

//���̾��תPID
UINT32 HandleToPid(IN HANDLE ProcessID, IN HANDLE handle)
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
		return (UINT32)pbi.UniqueProcessId;
	}
	return 0;
}

//�Ϸ�����TRUE�����򷵻�FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
	//����HANDLE_TABLE_ENTRY�Ľṹcd86788f 2050ffff 00000000 001fffff����dq����������
	if (!pHandleTableEntry->name1.name1.ObjectPointerBits) //handerͷһ��Ҫ��ֵ
		return FALSE;
	if (!pHandleTableEntry->name2.name1.GrantedAccessBits) //Ȩ��һ��Ҫ��ֵ
		return FALSE;
	if (pHandleTableEntry->name2.HighValue >> 25) //��λȥ��Ȩ�޺�Ӧ����0�������ֵ����ô������ʵ��淶
		return FALSE;
	return TRUE;
}

ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
	return ((addr->name1.LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}




void ����ָ���������о��_WIN10(HANDLE ProcessId)
{
	NTSTATUS status;
	PEPROCESS pEProcess = 0;
	status = PsLookupProcessByProcessId(ProcessId, &pEProcess);
	if (!NT_SUCCESS(status))
		return;

	__debugbreak();


	//ָ��ָ��HANDLE_TABLE
	UINT_PTR pProcessHandleTable = (UINT_PTR)pEProcess + Win10_EPROCESS_HANDLE_TABLE_OFFSET;
	UINT_PTR handleTable = RP(pProcessHandleTable);


	__try {
		//��ȡ�������
		ULONG cs = 0x1000000;//��������ô���
		ULONG count = 0;
		KdPrint(("����:SYS handleCount=%X   +++++++>>>>>>>>>\n\n", count));
		PVOID object = NULL;
		POBJECT_TYPE objectType = NULL;
		PWCH type = NULL;
		UINT32 error = 0;
		for (UINT32 i = 1; i <= cs; i++) {
			UINT_PTR handle = i * 4;//���

			HANDLE_TABLE_ENTRY* info = (HANDLE_TABLE_ENTRY*)MyExpLookupHandleTableEntry(handleTable, handle);

			//һ��Ҫ���ú�Win10_ExpLookupHandleTableEntry�����������
			//PExpLookupHandleTableEntry ExpLookupHandleTableEntryZ = (PExpLookupHandleTableEntry)Win10_ExpLookupHandleTableEntry;
			//PHANDLE_TABLE a = (PHANDLE_TABLE)handleTable;
			//EXHANDLE b;
			//b.Value = (ULONG64)handle;
			//UINT_PTR info1 = (UINT_PTR)ExpLookupHandleTableEntryZ(a, b);
			//KdPrint(("����:SYS info=%p  info1=%p   +++++++>>>>>>>>>\n\n", info,info1));

			if (!CheckHandleTableEntry(info)) { //������û��ͨ��У��,ֱ�ӽ���
				//���ﻹ��Ҫ�ж�һ�� ����������ʱ�ͷţ���������������10�Σ����У�鶼û�й�����ôһ���ǽ�����
				if (error < 10)
				{
					error++; continue;
				}
				else
					break;
			}
			else
			{
				error = 0;
			}
			count++;//ÿһ���Եľ����Ҫ����
			KdPrint(("����:SYS ���=%llX, info=%p,Ȩ��=%X  +++++++>>>>>>>>>\n", handle, info, (info->name2).name1.GrantedAccessBits));
			//��ȡobject
			*(ULONG_PTR*)&object = (ULONG_PTR)info->name1.name1.ObjectPointerBits;//��ȡobject����,���ֵֻ��44λ
			*(ULONG_PTR*)&object <<= 4;  //object�������ұ߼Ӹ�0x0;  �ұ߲�4λ
			*(ULONG_PTR*)&object |= 0xFFFF000000000000;  //��߲�16λ   �ܼ�64=44+4+16
			*(ULONG_PTR*)&object += 0x30;  //ƫ�� ��ȡobject��body

			objectType = (POBJECT_TYPE)ObGetObjectType(object);
			if (objectType == NULL)
			{
				KdPrint(("���: 0x%llX, info=%p  Object Type: 0  object: 0 \n", handle, info));
				continue;
			}
			
			type = objectType->Name.Buffer;
			KdPrint(("���: 0x%llX,  info=%p  Object Type: %S  object: %p \n", handle, info, type, object));

			if (type && _wcsicmp(L"Process", type) == 0) {
				//UINT32 ��Ȩ�� = 0x1FFFFF;
				UINT32 ��Ȩ�� = 0x0;
				info->name2.name1.GrantedAccessBits = ��Ȩ��;
				KdPrint(("yjx:SYS ���=%llX, Ȩ��=%X ,���ӽ���PID=%d +++++++>>>>>>>>>\n",
					handle, info->name2.name1.GrantedAccessBits, HandleToPid(ProcessId, (HANDLE)handle)));
			}
			KdPrint(("\n"));
		}
		KdPrint(("����:SYS �������=%X   +++++++>>>>>>>>>\n\n", count));
	}
	__except (1) {
		KdPrint(("����:SYS �쳣��  +++++++>>>>>>>>>\n\n"));
	}
}

NTSTATUS IRP_ͨ�����̱������(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	int* ������ = pirp->AssociatedIrp.SystemBuffer;
	if (������) {
		UINT64* pPID = (UINT64*)������;
		UINT64 pid = pPID[0];
		����ָ���������о��_WIN10((HANDLE)pid);
		KdPrint(("���� ͨ�����̱������ %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	}
	return STATUS_SUCCESS;
}