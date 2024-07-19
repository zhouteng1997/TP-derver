#include<ntifs.h>
#include "win10结构体.h"

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

void 遍历指定进提所有句柄_WIN10(HANDLE ProcessId)
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

	KdPrint(("驱动:SYS process=%llX \nphandleTable = %llX \ntableCode = %llX \n++++++ + >>>>>>>>>\n\n",
		(UINT_PTR)process, phandleTable, tableCode));

	if (handletable == NULL) return;

	__try {
		//获取句柄数量
		ULONG count = GetHandleCount(handletable);
		KdPrint(("驱动:SYS handleCount=%X   +++++++>>>>>>>>>\n\n", count));
		//PVOID object = NULL;
		//POBJECT_TYPE objectType = NULL;
		for (UINT32 i = 1; i <= count - 1; i++) {
			UINT_PTR handle = i * 4;//句柄
			HANDLE_TABLE_ENTRY* info = (HANDLE_TABLE_ENTRY*)MyExpLookupHandleTableEntry(tableCode, handle);
			if (info == NULL) {
				break;
			}
			else {

				KdPrint(("驱动:SYS 句柄=%llX, info=%p,权限=%X  +++++++>>>>>>>>>\n\n", handle, info, (info->name4).name1.GrantedAccessBits));
				//获取object
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
			// 获取句柄类型信息
			//POBJECT_TYPE objectType = GetHandleType((HANDLE)handle);
			//if (objectType) {
			//	UNICODE_STRING* typename = &objectType->Name;
			//	KdPrint(("Handle: 0x%llX, Object Type: %S\n", handle, typename->Buffer));
			//}

			//PVOID object = NULL;
			//POBJECT_TYPE objectType = NULL;
			//PWCH type = NULL;
			//// 获取对象指针
			//NTSTATUS status = ObReferenceObjectByHandle((HANDLE)handle, 0, NULL, KernelMode, &object, NULL);
			//if (NT_SUCCESS(status)) {
			//	// 通过对象指针获取对象类型信息
			//	objectType = *(POBJECT_TYPE*)((ULONG_PTR)object + sizeof(PVOID));
			//	// 释放对象引用
			//	ObDereferenceObject(object);
			//	type=objectType->Name.Buffer;
			//	if (type && _wcsicmp(L"Process", type)==0) {
			//		UINT32 新权限 = 0x1FFFFF;
			//		info->name4.name1.GrantedAccessBits = 新权限;
			//	}
			//}
			/*KdPrint(("yjx:SYS 句柄=%llX, info=%p,权限=%X 类型 =%S  +++++++>>>>>>>>>\n\n", handle, info,(info->name4).name1.GrantedAccessBits, type));*/
		}
	}
	__except (1) {

	}

}











NTSTATUS IRP_通过进程遍历句柄(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	int* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区) {
		UINT64* pPID = (UINT64*)缓冲区;
		UINT64 pid = pPID[0];
		遍历指定进提所有句柄_WIN10((HANDLE)pid);
		KdPrint(("驱动 通过进程遍历句柄 %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	}
	return STATUS_SUCCESS;
}