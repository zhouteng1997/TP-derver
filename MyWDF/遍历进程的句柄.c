#include<ntifs.h>
#include "win10�ṹ��.h"

#define TYPE_INDEX_OFFSET 0x18
#define OB_HEADER_COOKIE 0x21
#define PROCESS_TYPE 7


typedef PHANDLE_TABLE_ENTRY(*PExpLookupHandleTableEntry)(
	IN PHANDLE_TABLE HandleTable,//����1�Ǿ����ĵ�ַ���� HandleTable��ע�⣬���� HandleTable �ĵ�λ������Ҫ��������Ҫ�жϾ����ṹ��
	IN EXHANDLE handle//����2�Ǿ��ֵ��PID ��ֵ����һ�����ֵ������ 0perproces ��һ�����̵õ���Ҳ�Ǿ��ֵ��ǰ����������ȫ�־�������������������̵ľ�±�
	);


BOOLEAN IsProcess(PVOID64 Address)
{
	UINT8 uTypeIndex;
	UINT8 uByte;

	uByte = ((ULONG64)Address >> 8) & 0xff;
	uTypeIndex = *(PCHAR)((PCHAR)Address + TYPE_INDEX_OFFSET);
	uTypeIndex = uTypeIndex ^ OB_HEADER_COOKIE ^ uByte;

	if (uTypeIndex == PROCESS_TYPE) {
		return TRUE;
	}

	return FALSE;
}

//�Ϸ�����TRUE�����򷵻�FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
	if (!pHandleTableEntry->name1.LowValue) {
		return FALSE;
	}
	return TRUE;
}

ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
	return ((addr->name1.LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}

UINT_PTR ObGetObjectType(PVOID object);


void ����ָ���������о��_WIN10(HANDLE ProcessId)
{
	NTSTATUS status;
	PEPROCESS pProcess = 0;
	status = PsLookupProcessByProcessId(ProcessId, &pProcess);
	if (!NT_SUCCESS(status))
		return;

	__debugbreak();


	//ָ��ָ��HANDLE_TABLE
	UINT_PTR pProcessHandleTable = (UINT_PTR)pProcess + Win10_EPROCESS_HANDLE_TABLE_OFFSET;
	UINT_PTR handleTable = RP(pProcessHandleTable);


	__try {
		INT32 error = 0;
		//��ȡ�������
		ULONG cs = 0x1000000;//��������ô���
		ULONG count = 0;
		KdPrint(("����:SYS handleCount=%X   +++++++>>>>>>>>>\n\n", count));
		PVOID object = NULL;
		POBJECT_TYPE objectType = NULL;
		for (UINT32 i = 1; i <= cs; i++) {
			UINT_PTR handle = i * 4;//���

			HANDLE_TABLE_ENTRY* info = (HANDLE_TABLE_ENTRY*)MyExpLookupHandleTableEntry(handleTable, handle);

			PExpLookupHandleTableEntry ExpLookupHandleTableEntryZ = (PExpLookupHandleTableEntry)Win10_ExpLookupHandleTableEntry;
			PHANDLE_TABLE a = (PHANDLE_TABLE)handleTable;
			EXHANDLE b;
			b.Value = (ULONG64)handle;
			UINT_PTR info1 = (UINT_PTR)ExpLookupHandleTableEntryZ(a, b);

			KdPrint(("����:SYS info=%p  info1=%p   +++++++>>>>>>>>>\n\n", info,info1));
			// ���tablecode���쳣��������� ����10�������ˣ�˵���Ѿ�������
			if (!CheckHandleTableEntry(info)) {
				if (error > 10)
				{
					break;
				}
				error = error + 1;
				continue;
			}
			error = 0;
			count++;//ÿһ���Եľ����Ҫ����
			KdPrint(("����:SYS ���=%llX, info=%p,Ȩ��=%X  +++++++>>>>>>>>>\n\n", handle, info, (info->name4).name1.GrantedAccessBits));
			//��ȡobject
			*(ULONG_PTR*)&object = (ULONG_PTR)info->name3.name1.ObjectPointerBits;
			*(ULONG_PTR*)&object <<= 4;
			if (object == NULL)
			{
				continue;
			}
			*(ULONG_PTR*)&object |= 0xFFFF000000000000;
			*(ULONG_PTR*)&object += 0x30;
			objectType = (POBJECT_TYPE)ObGetObjectType(object);
			if (objectType == NULL)
			{
				KdPrint(("Handle: 0x%llX, Object Type: 0 \n", handle));
				continue;
			}
			UNICODE_STRING* typename = &objectType->Name;
			KdPrint(("Handle: 0x%llX, Object Type: %S\n", handle, typename->Buffer));
		}
		KdPrint(("����:SYS �������=%X   +++++++>>>>>>>>>\n\n", count));
		//��ȡ���������Ϣ
		//POBJECT_TYPE objectType = GetHandleType((HANDLE)handle);
		//if (objectType) {
		//	UNICODE_STRING* typename = &objectType->Name;
		//	KdPrint(("Handle: 0x%llX, Object Type: %S\n", handle, typename->Buffer));
		//}

		//PVOID object = NULL;
		//POBJECT_TYPE objectType = NULL;
		//PWCH type = NULL;
		//// ��ȡ����ָ��
		//NTSTATUS status = ObReferenceObjectByHandle((HANDLE)handle, 0, NULL, KernelMode, &object, NULL);
		//if (NT_SUCCESS(status)) {
		//	// ͨ������ָ���ȡ����������Ϣ
		//	objectType = *(POBJECT_TYPE*)((ULONG_PTR)object + sizeof(PVOID));
		//	// �ͷŶ�������
		//	ObDereferenceObject(object);
		//	type = objectType->Name.Buffer;
		//	if (type && _wcsicmp(L"Process", type) == 0) {
		//		UINT32 ��Ȩ�� = 0x1FFFFF;
		//		info->name4.name1.GrantedAccessBits = ��Ȩ��;
		//	}
		//}
		/*KdPrint(("yjx:SYS ���=%llX, info=%p,Ȩ��=%X ���� =%S  +++++++>>>>>>>>>\n\n", handle, info,(info->name4).name1.GrantedAccessBits, type));*/

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