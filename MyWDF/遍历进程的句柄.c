#include<ntifs.h>
#include "win10结构体.h"

#define TYPE_INDEX_OFFSET 0x18
#define OB_HEADER_COOKIE 0x21
#define PROCESS_TYPE 7


typedef PHANDLE_TABLE_ENTRY(*PExpLookupHandleTableEntry)(
	IN PHANDLE_TABLE HandleTable,//参数1是句柄表的地址，即 HandleTable，注意，这里 HandleTable 的低位不能清要，函数里要判断句柄表结构的
	IN EXHANDLE handle//参数2是句柄值，PID 的值就是一个句柄值，调用 0perproces 打开一个进程得到的也是句柄值，前者用来索引全局句柄表，后者用来索引进程的句柯表。
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

//合法返回TRUE，否则返回FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
	//分析HANDLE_TABLE_ENTRY的结构cd86788f 2050ffff 00000000 001fffff这是dq出来的数据
	if (!pHandleTableEntry->name1.name1.ObjectPointerBits) //hander头一定要有值
		return FALSE;
	if (!pHandleTableEntry->name2.name1.GrantedAccessBits) //权限一定要有值
		return FALSE;
	if (pHandleTableEntry->name2.HighValue >> 25) //高位去除权限后，应该是0，如果有值，那么不符合实体规范
		return FALSE;
	return TRUE;
}

ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
	return ((addr->name1.LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}

UINT_PTR ObGetObjectType(PVOID object);


void 遍历指定进提所有句柄_WIN10(HANDLE ProcessId)
{
	NTSTATUS status;
	PEPROCESS pProcess = 0;
	status = PsLookupProcessByProcessId(ProcessId, &pProcess);
	if (!NT_SUCCESS(status))
		return;

	__debugbreak();


	//指针指向HANDLE_TABLE
	UINT_PTR pProcessHandleTable = (UINT_PTR)pProcess + Win10_EPROCESS_HANDLE_TABLE_OFFSET;
	UINT_PTR handleTable = RP(pProcessHandleTable);


	__try {
		//获取句柄数量
		ULONG cs = 0x1000000;//最多遍历这么多次
		ULONG count = 0;
		KdPrint(("驱动:SYS handleCount=%X   +++++++>>>>>>>>>\n\n", count));
		PVOID object = NULL;
		POBJECT_TYPE objectType = NULL;
		UINT32 error = 0;
		for (UINT32 i = 1; i <= cs; i++) {
			UINT_PTR handle = i * 4;//句柄

			HANDLE_TABLE_ENTRY* info = (HANDLE_TABLE_ENTRY*)MyExpLookupHandleTableEntry(handleTable, handle);

			//一定要配置好Win10_ExpLookupHandleTableEntry，否则会蓝屏
			//PExpLookupHandleTableEntry ExpLookupHandleTableEntryZ = (PExpLookupHandleTableEntry)Win10_ExpLookupHandleTableEntry;
			//PHANDLE_TABLE a = (PHANDLE_TABLE)handleTable;
			//EXHANDLE b;
			//b.Value = (ULONG64)handle;
			//UINT_PTR info1 = (UINT_PTR)ExpLookupHandleTableEntryZ(a, b);
			//KdPrint(("驱动:SYS info=%p  info1=%p   +++++++>>>>>>>>>\n\n", info,info1));

			if (!CheckHandleTableEntry(info)) { //如果句柄没有通过校验,直接结束
				//这里还需要判断一下 这个句柄被暂时释放，所以我们连续连10次，如果校验都没有过，那么一定是结束了
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
			count++;//每一个对的句柄都要计数
			KdPrint(("驱动:SYS 句柄=%llX, info=%p,权限=%X  +++++++>>>>>>>>>\n", handle, info, (info->name2).name1.GrantedAccessBits));
			//获取object
			*(ULONG_PTR*)&object = (ULONG_PTR)info->name1.name1.ObjectPointerBits;//获取object对象,这个值只有44位
			*(ULONG_PTR*)&object <<= 4;  //object对象最右边加个0x0;  右边补4位
			*(ULONG_PTR*)&object |= 0xFFFF000000000000;  //左边补16位   总计64=44+4+16
			*(ULONG_PTR*)&object += 0x30;  //偏移 获取object的body

			objectType = (POBJECT_TYPE)ObGetObjectType(object);
			if (objectType == NULL)
			{
				KdPrint(("Handle: 0x%llX, Object Type: 0  object: 0 \n\n", handle));
				continue;
			}
			UNICODE_STRING* typename = &objectType->Name;
			KdPrint(("Handle: 0x%llX, Object Type: %S  object: %p \n\n", handle, typename->Buffer, object));
		}
		KdPrint(("驱动:SYS 句柄总数=%X   +++++++>>>>>>>>>\n\n", count));
		//获取句柄类型信息
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
		//	type = objectType->Name.Buffer;
		//	if (type && _wcsicmp(L"Process", type) == 0) {
		//		UINT32 新权限 = 0x1FFFFF;
		//		info->name4.name1.GrantedAccessBits = 新权限;
		//	}
		//}
		/*KdPrint(("yjx:SYS 句柄=%llX, info=%p,权限=%X 类型 =%S  +++++++>>>>>>>>>\n\n", handle, info,(info->name4).name1.GrantedAccessBits, type));*/

	}
	__except (1) {
		KdPrint(("驱动:SYS 异常了  +++++++>>>>>>>>>\n\n"));
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