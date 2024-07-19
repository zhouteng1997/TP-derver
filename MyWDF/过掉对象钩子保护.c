#include <ntifs.h>

#include "���̱���.h"

//����һ����������
NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

extern PSHORT NtBuildNumber;


// ��ȡδ�ĵ����ĺ���
PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName,
	IN PUCHAR pStartAddress,
	IN UCHAR* pFeatureCode,
	IN ULONG FeatureCodeNum,
	ULONG SerSize,
	UCHAR SegCode,
	ULONG AddNum,
	BOOLEAN ByName);

#define DRIVER_TAG 'qd'  // ����һ���׶��ı�ǣ����� 'DvrD'
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
	LIST_ENTRY NextEntryItemList;  // (callbacklist) �洢��һ��callbacklist
	ULONG64 Operations;
	PVOID ObHandle;  // �洢��ϸ������
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
FAST_MUTEX g_OperationListLock;  // �� g_OperationListHead �ӵ�ͬ���ֶ� ������
PVOID g_UpperHandle = NULL;
PVOID g_LowerHandle = NULL;

HANDLE GetCurrentProcessID()
{
	return PsGetCurrentProcessId();
}

// ���Լ��Ľ��� ���Թ�����
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

// �ں˻�ȡϵͳ��������
ULONG MyGetTickCount()
{
	LARGE_INTEGER la;
	ULONG MyInc;
	MyInc = KeQueryTimeIncrement();  // ���صδ���Ƶ��
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
			// ���������Ȩ�� ��ֹ�������ص� �޸� DuplicateHandle OpenProcess
			NewEntry->AccessMask = 0x1FFFFF;
			NewEntry->time = MyGetTickCount();

			ExAcquireFastMutex(&g_OperationListLock);
			InsertTailList(&g_OperationListHead, &NewEntry->ListEntry);
			KdPrint(("������Last_CallBack   ����Ȩ��=%llX PID=%llX time=%llX line=%lld\n",
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



	UINT_PTR ��ǰ����PID = (UINT_PTR)PsGetCurrentProcessId();//��ǰ����FID
	UINT_PTR Ŀ�����PID=(UINT_PTR)PsGetProcessId((PEPROCESS)OperationInformation->Object); // Ŀ�����PD��Ҫ�⻤��FI
	��ǰ����PID;
	Ŀ�����PID;

	if (�ж�����Ȩ��PID(��ǰ����PID)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;//�ո�Ȩ������
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0x1fffff;//�ո�Ȩ������;
		KdPrint(("���� : ��Ȩ line=%d \n", __LINE__));
		return OB_PREOP_SUCCESS;
	}
	else if (�ж��ܱ�����PID(Ŀ�����PID)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;//�ո�Ȩ������
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;//�ո�Ȩ������;
		return OB_PREOP_SUCCESS;
	}
	else if (IsMyProcess())
	{
		OperationInformation -> Parameters ->CreateHandleInformation.DesiredAccess = 0x1fffff;//�ո�Ȩ������
		OperationInformation -> Parameters->DuplicateHandleInformation.DesiredAccess = 0x1fffff;//�ո�Ȩ������;
		KdPrint(("���� :MinCAllEack SYS ��ԭ,,,line=%d \n", __LINE__));
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

	//			KdPrint(("������SYS First_CallBack  PID=%llX <ԭȨ��=%llX,��Ȩ��=%llX>----->time=%llX line=%d\n",
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

// XignCode3 �ص��� 380800
// EAC       �ص��� 327530
// BE        �ص��� 363220
OB_CALLBACK_REGISTRATION UpperCallbackRegistration =
{
	OB_FLT_REGISTRATION_VERSION,
	2,
	RTL_CONSTANT_STRING(L"880000"), // �ߵ�
	NULL,
	ObUpperOperationRegistration
};

OB_CALLBACK_REGISTRATION LowerCallcackRegistration =
{
	OB_FLT_REGISTRATION_VERSION,
	2,
	RTL_CONSTANT_STRING(L"10000"), // �͵�
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
