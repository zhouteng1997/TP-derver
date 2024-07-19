#include<ntifs.h>
#include "win10�ṹ��.h"

UINT_PTR ObGetObjectType(PVOID object);

ULONG GetHandleCount(PHANDLE_TABLE HandleTable) {
	ULONG count = 0;
	PLIST_ENTRY entry = &HandleTable->HandleTableList;
	PLIST_ENTRY current = entry->Flink;

	while (current != entry) {
		count++;
		current = current->Flink;
	}

	return count;
}

void ����ָ���������о��_WIN10(HANDLE ProcessId)
{
	NTSTATUS status;
	PEPROCESS process = 0;
	status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status))
		return;

	__debugbreak();



	UINT_PTR processHandleTable = (UINT_PTR)process + Win10_EPROCESS_HANDLE_TABLE_OFFSET;
	UINT_PTR phandleTable = RP(processHandleTable);
	UINT_PTR p_HANDLE_TABLE_TableCode = phandleTable + Win10_HANDLE_TABLE_TableCode_OFFSET;
	UINT_PTR tableCode = RP(p_HANDLE_TABLE_TableCode);
	HANDLE_TABLE* handletable = (HANDLE_TABLE*)phandleTable;

	KdPrint(("����:SYS process=%llX \nphandleTable = %llX \ntableCode = %llX \n++++++ + >>>>>>>>>\n\n",
		(UINT_PTR)process, phandleTable, tableCode));

	if (handletable == NULL) return;

	__try {
		//��ȡ�������
		ULONG count = GetHandleCount(handletable);
		KdPrint(("����:SYS handleCount=%X   +++++++>>>>>>>>>\n\n", count));
		//PVOID object = NULL;
		//POBJECT_TYPE objectType = NULL;
		for (UINT32 i = 1; i <= count - 1; i++) {
			UINT_PTR handle = i * 4;//���
			HANDLE_TABLE_ENTRY* info = (HANDLE_TABLE_ENTRY*)MyExpLookupHandleTableEntry(tableCode, handle);
			if (info == NULL) {
				break;
			}
			else {

				KdPrint(("����:SYS ���=%llX, info=%p,Ȩ��=%X  +++++++>>>>>>>>>\n\n", handle, info, (info->name4).name1.GrantedAccessBits));
				//��ȡobject
				//*(ULONG_PTR*)&object = (ULONG_PTR)info->name3.name1.ObjectPointerBits;
				//*(ULONG_PTR*)&object <<= 4;
				//if (object == NULL)
				//{
				//	continue;
				//}
				//*(ULONG_PTR*)&object |= 0xFFFF000000000000;
				//*(ULONG_PTR*)&object += 0x30;
				//objectType = (POBJECT_TYPE)ObGetObjectType(object);
				//if (objectType == NULL)
				//{
				//	KdPrint(("Handle: 0x%llX, Object Type: 0 \n", handle));
				//	continue;
				//}
				//UNICODE_STRING* typename = &objectType->Name;
				//KdPrint(("Handle: 0x%llX, Object Type: %S\n", handle, typename->Buffer));

			}
			// ��ȡ���������Ϣ
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
			//	type=objectType->Name.Buffer;
			//	if (type && _wcsicmp(L"Process", type)==0) {
			//		UINT32 ��Ȩ�� = 0x1FFFFF;
			//		info->name4.name1.GrantedAccessBits = ��Ȩ��;
			//	}
			//}
			/*KdPrint(("yjx:SYS ���=%llX, info=%p,Ȩ��=%X ���� =%S  +++++++>>>>>>>>>\n\n", handle, info,(info->name4).name1.GrantedAccessBits, type));*/
		}
	}
	__except (1) {

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