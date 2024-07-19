#include <ntifs.h>

#include "进程保护.h"

//这是一个申明函数
NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

extern PSHORT NtBuildNumber;


// 获取未文档化的函数
PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName,
	IN PUCHAR pStartAddress,
	IN UCHAR* pFeatureCode,
	IN ULONG FeatureCodeNum,
	ULONG SerSize,
	UCHAR SegCode,
	ULONG AddNum,
	BOOLEAN ByName);

#define DRIVER_TAG 'qd'  // 定义一个易读的标记，例如 'DvrD'
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

ULONG ObjectCallbackListOffset = 0;

typedef struct _LDR_DATA
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		} LDR_DATA_1;
	} LDR_DATA_2;
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	} LDR_DATA_3;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
	PVOID ContextInformation;
	UINT64 OriginalBase;
	union _LARGE_INTEGER LoadTime;
} LDR_DATA, * PLDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		} LDR_DATA_TABLE_ENTRY_1;
	} LDR_DATA_TABLE_ENTRY_2;
	union
	{
		struct
		{
			ULONG TimeDateStamp;
		} LDR_DATA_TABLE_ENTRY_3;
		struct
		{
			PVOID LoadedImports;
		} LDR_DATA_TABLE_ENTRY_4;
	} LDR_DATA_TABLE_ENTRY_5;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OPERATION_INFO_ENTRY
{
	LIST_ENTRY ListEntry;
	OB_OPERATION Operation;
	ULONG Flags;
	PVOID Object;
	POBJECT_TYPE ObjectType;
	ACCESS_MASK AccessMask;
	ULONG32 time;
} OPERATION_INFO_ENTRY, * POPERATION_INFO_ENTRY;

typedef struct _CALL_BACK_INFO
{
	ULONG64 Unknow;
	ULONG64 Unknow1;
	UNICODE_STRING AltitudeString;
	LIST_ENTRY NextEntryItemList;  // (callbacklist) 存储下一个callbacklist
	ULONG64 Operations;
	PVOID ObHandle;  // 存储详细的数据
	PVOID ObjectType;
	ULONG64 PreCallbackAddr;
	ULONG64 PostCallbackAddr;
} CALL_BACK_INFO, * PCALL_BACK_INFO;

typedef struct _OB_CALLBACK
{
	LIST_ENTRY ListEntry;
	ULONG64 Operations;
	PCALL_BACK_INFO ObHandle;
	ULONG64 ObjTypeAddr;
	ULONG64 PreCall;
	ULONG64 PostCall;
} OB_CALLBACK, * POB_CALLBACK;

LIST_ENTRY g_OperationListHead;
FAST_MUTEX g_OperationListLock;  // 给 g_OperationListHead 加的同步手段 互斥体
PVOID g_UpperHandle = NULL;
PVOID g_LowerHandle = NULL;

HANDLE GetCurrentProcessID()
{
	return PsGetCurrentProcessId();
}

// 是自己的进程 可以过保护
BOOLEAN IsMyProcess()
{
	PEPROCESS Process = PsGetCurrentProcess();
	if (_strnicmp("8264.exe", (char*)PsGetProcessImageFileName(Process), strlen("8264.exe")) == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

// 内核获取系统启动计数
ULONG MyGetTickCount()
{
	LARGE_INTEGER la;
	ULONG MyInc;
	MyInc = KeQueryTimeIncrement();  // 返回滴答数频率
	KeQueryTickCount(&la);
	la.QuadPart *= MyInc;
	la.QuadPart /= 10000;
	return la.LowPart;
}

// APC_LEVEL=1;
OB_PREOP_CALLBACK_STATUS Last_CallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	POPERATION_INFO_ENTRY NewEntry = NULL;

	if (PsGetCurrentProcess() == PsInitialSystemProcess)
		return OB_PREOP_SUCCESS;

	if (OperationInformation->ObjectType == *(POBJECT_TYPE*)PsThreadType)
		return OB_PREOP_SUCCESS;

	if (IsMyProcess())
	{
		PVOID sss = (PVOID)ExAllocatePoolWithTag(NonPagedPool, sizeof(OPERATION_INFO_ENTRY), (ULONG)0);
		NewEntry=(POPERATION_INFO_ENTRY)sss;

		if (NewEntry)
		{
			NewEntry->Operation = OperationInformation->Operation;
			NewEntry->Flags = OperationInformation->Flags;
			NewEntry->Object = OperationInformation->Object;
			NewEntry->ObjectType = OperationInformation->ObjectType;
			// 保存请求的权限 防止被保护回调 修改 DuplicateHandle OpenProcess
			NewEntry->AccessMask = 0x1FFFFF;
			NewEntry->time = MyGetTickCount();

			ExAcquireFastMutex(&g_OperationListLock);
			InsertTailList(&g_OperationListHead, &NewEntry->ListEntry);
			KdPrint(("驱动：Last_CallBack   保存权限=%llX PID=%llX time=%llX line=%lld\n",
				(ULONG64)OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				(ULONG64)PsGetCurrentProcessId(),
				(ULONG64)NewEntry->time,
				(ULONG64)__LINE__));
			ExReleaseFastMutex(&g_OperationListLock);
		}
	}

	UNREFERENCED_PARAMETER(RegistrationContext);

	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS First_CallBack(IN PVOID RegistrationContext, IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	//POPERATION_INFO_ENTRY NewEntry = NULL;
	//if (PsGetCurrentProcess()== PsInitialSystemProcess)
	//	return OB_PREOP_SUCCESS;
	//if (OperationInformation->ObjectType == PsThreadType)
	//		return OB_PREOP_SUCCESS;



	UINT_PTR 当前进程PID = (UINT_PTR)PsGetCurrentProcessId();//当前进程FID
	UINT_PTR 目标进程PID=(UINT_PTR)PsGetProcessId((PEPROCESS)OperationInformation->Object); // 目标进程PD想要蒜护的FI
	当前进程PID;
	目标进程PID;

	if (判断需提权的PID(当前进程PID)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;//收复权限请求
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0x1fffff;//收复权限请求;
		KdPrint(("驱动 : 提权 line=%d \n", __LINE__));
		return OB_PREOP_SUCCESS;
	}
	else if (判断受保护的PID(目标进程PID)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;//收复权限请求
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;//收复权限请求;
		return OB_PREOP_SUCCESS;
	}
	else if (IsMyProcess())
	{
		OperationInformation -> Parameters ->CreateHandleInformation.DesiredAccess = 0x1fffff;//收复权限请求
		OperationInformation -> Parameters->DuplicateHandleInformation.DesiredAccess = 0x1fffff;//收复权限请求;
		KdPrint(("驱动 :MinCAllEack SYS 还原,,,line=%d \n", __LINE__));
		return OB_PREOP_SUCCESS;
	}

	//if (IsMyProcess())
	//{
	// 	PLIST_ENTRY ListEntry;
	//	ExAcquireFastMutex(&g_OperationListLock);
	//	for (ListEntry = g_OperationListHead.Flink; ListEntry != &g_OperationListHead; ListEntry = ListEntry->Flink)
	//	{
	//		POPERATION_INFO_ENTRY Entry = (POPERATION_INFO_ENTRY)ListEntry;
	//		if (Entry->Operation == OperationInformation->Operation &&
	//			Entry->Flags == OperationInformation->Flags &&
	//			Entry->Object == OperationInformation->Object &&
	//			Entry->ObjectType == OperationInformation->ObjectType)
	//		{
	//			ULONG32 newAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

	//			ULONG32 oldAccess =(ULONG32)Entry->AccessMask;
	//			oldAccess;

	//			KdPrint(("驱动：SYS First_CallBack  PID=%llX <原权限=%llX,新权限=%llX>----->time=%llX line=%d\n",
	//				(ULONG64)PsGetCurrentProcessId(),
	//				(ULONG64)(Entry->AccessMask),
	//				(ULONG64)newAccess,
	//				(ULONG64)Entry->time, (ULONG64)__LINE__));

	//			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = Entry->AccessMask;
	//			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = Entry->AccessMask;

	//			RemoveEntryList(&Entry->ListEntry);
	//			ExFreePoolWithTag(Entry, DRIVER_TAG);
	//			goto Release;
	//		}
	//	}
	//Release:
	//	ExReleaseFastMutex(&g_OperationListLock);
	//}

	return OB_PREOP_SUCCESS;
}

OB_OPERATION_REGISTRATION ObUpperOperationRegistration[] =
{
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, Last_CallBack, NULL },
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, Last_CallBack, NULL },
};

OB_OPERATION_REGISTRATION ObLowerOperationRegistration[] =
{
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, First_CallBack, NULL },
	{ NULL, OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, First_CallBack, NULL },
};

// XignCode3 回调码 380800
// EAC       回调码 327530
// BE        回调码 363220
OB_CALLBACK_REGISTRATION UpperCallbackRegistration =
{
	OB_FLT_REGISTRATION_VERSION,
	2,
	RTL_CONSTANT_STRING(L"880000"), // 高的
	NULL,
	ObUpperOperationRegistration
};

OB_CALLBACK_REGISTRATION LowerCallcackRegistration =
{
	OB_FLT_REGISTRATION_VERSION,
	2,
	RTL_CONSTANT_STRING(L"10000"), // 低的
	NULL,
	ObLowerOperationRegistration
};

void ObRegisterUnload()
{
	if (NULL != g_LowerHandle)
		ObUnRegisterCallbacks(g_LowerHandle);
	if (NULL != g_UpperHandle)
		ObUnRegisterCallbacks(g_UpperHandle);
	while (!IsListEmpty(&g_OperationListHead))
		ExFreePoolWithTag(RemoveHeadList(&g_OperationListHead), DRIVER_TAG);
}

BOOLEAN ObRegisterCallBacksInit(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PLDR_DATA ldr;

	ldr = (PLDR_DATA)pDriverObject->DriverSection;
	ldr->Flags |= 0x20;

	InitializeListHead(&g_OperationListHead);
	ExInitializeFastMutex(&g_OperationListLock);

	ObUpperOperationRegistration[0].ObjectType = PsProcessType;
	ObUpperOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	ObUpperOperationRegistration[1].ObjectType = PsThreadType;
	ObUpperOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	Status = ObRegisterCallbacks(&UpperCallbackRegistration, &g_UpperHandle);
	if (!NT_SUCCESS(Status))
	{
		g_UpperHandle = NULL;
		goto Exit;
	}

	ObLowerOperationRegistration[0].ObjectType = PsProcessType;
	ObLowerOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	ObLowerOperationRegistration[1].ObjectType = PsThreadType;
	ObLowerOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	Status = ObRegisterCallbacks(&LowerCallcackRegistration, &g_LowerHandle);
	if (!NT_SUCCESS(Status))
	{
		g_LowerHandle = NULL;
		goto Exit;
	}

Exit:
	if (!NT_SUCCESS(Status))
		ObRegisterUnload();

	return NT_SUCCESS(Status) ? TRUE : FALSE;
}
