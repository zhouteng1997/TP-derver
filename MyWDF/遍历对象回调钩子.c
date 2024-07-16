#include <ntifs.h>

//����ȫ�ֱ����ͺ���ԭ��
static ULONG ObjectCallbackListOffset = 0;  //����ص��б�ƫ����
extern PSHORT NtBuildNumber;  //NtBuildNumber���ⲿ����


PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName,
	IN PUCHAR pStartAddress,
	IN UCHAR* pFeatureCode,
	IN ULONG FeatureCodeNum,
	ULONG SerSize,
	UCHAR SegCode,
	ULONG AddNum,
	BOOLEAN ByName);

//LDR_DATA�ṹ��Ķ���
typedef struct _LDR_DATA {
	struct _LIST_ENTRY InLoadOrderLinks;
	struct _LIST_ENTRY InMemoryOrderLinks;
	struct _LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;  //ģ���ַ
	VOID* EntryPoint;  //��ڵ�
	ULONG32 SizeOfImage;  //ģ���С
	UINT8 _PADDING0_[0x4];  //����ֽ�
	struct _UNICODE_STRING FullDllName;  //������DLL����
	struct _UNICODE_STRING BaseDllName;  //������DLL����
	ULONG32 Flags;  //��־
	UINT16 LoadCount;  //���ؼ���
	UINT16 TlsIndex;  //TLS����
	union {
		struct _LIST_ENTRY HashLinks;
		struct {
			VOID* SectionPointer;  //��ָ��
			ULONG32 CheckSum;  //У���
			UINT8 _PADDING1_[0x4];  //����ֽ�
		}LDR_DATA_1;
	}LDR_DATA_2;
	union {
		ULONG32 TimeDateStamp;  //ʱ���
		VOID* LoadedImports;  //�Ѽ��صĵ�����
	}LDR_DATA_3;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;  //��ڵ㼤��������
	VOID* PatchInformation;  //������Ϣ
	struct _LIST_ENTRY ForwarderLinks;  //ת������
	struct _LIST_ENTRY ServiceTagLinks;  //�����ǩ����
	struct _LIST_ENTRY StaticLinks;  //��̬����
	VOID* ContextInformation;  //��������Ϣ
	UINT64 OriginalBase;  //ԭʼ��ַ
	union _LARGE_INTEGER LoadTime;  //����ʱ��
} LDR_DATA, * PLDR_DATA;

//LDR_DATA_TABLE_ENTRY�ṹ��Ķ���
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;  //ģ���ַ
	PVOID EntryPoint;  //��ڵ�
	ULONG SizeOfImage;  //ģ���С
	UNICODE_STRING FullDllName;  //������DLL����
	UNICODE_STRING BaseDllName;  //������DLL����
	ULONG Flags;  //��־
	USHORT LoadCount;  //���ؼ���
	USHORT TlsIndex;  //TLS����
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;  //��ָ��
			ULONG CheckSum;  //У���
		}LDR_DATA_TABLE_ENTRY_1;
	}LDR_DATA_TABLE_ENTRY_2;
	union {
		struct {
			ULONG TimeDateStamp;  //ʱ���
		}LDR_DATA_TABLE_ENTRY_3;
		struct {
			PVOID LoadedImports;  //�Ѽ��صĵ�����
		}LDR_DATA_TABLE_ENTRY_4;
	}LDR_DATA_TABLE_ENTRY_5;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;  //��ڵ㼤��������
	PVOID PatchInformation;  //������Ϣ
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//OPERATION_INFO_ENTRY�ṹ��Ķ���
typedef struct _OPERATION_INFO_ENTRY {
	LIST_ENTRY ListEntry;
	OB_OPERATION Operation;  //����
	ULONG Flags;  //��־
	PVOID Object;  //����
	POBJECT_TYPE ObjectType;  //��������
	ACCESS_MASK AccessMask;  //��������
	ULONG32 time;  //ʱ��
} OPERATION_INFO_ENTRY, * POPERATION_INFO_ENTRY;

//CALL_BACK_INFO�ṹ��Ķ���
typedef struct _CALL_BACK_INFO {
	ULONG64 Unknow;
	ULONG64 Unknow1;
	UNICODE_STRING AltitudeString;  //�߶��ַ���
	LIST_ENTRY NextEntryItemList;  //��һ�����б�
	ULONG64 Operations;  //����
	PVOID ObHandle;  //������
	PVOID ObjectType;  //��������
	ULONG64 PreCallbackAddr;  //ǰ�ص���ַ
	ULONG64 PostCallbackAddr;  //��ص���ַ
} CALL_BACK_INFO, * PCALL_BACK_INFO;

//OB_CALLBACK�ṹ��Ķ���
typedef struct _OB_CALLBACK {
	LIST_ENTRY ListEntry;
	ULONG64 Operations;  //����
	PCALL_BACK_INFO ObHandle;  //������
	ULONG64 ObjTypeAddr;  //�������͵�ַ
	ULONG64 PreCall;  //ǰ����
	ULONG64 PostCall;  //�����
} OB_CALLBACK, * POB_CALLBACK;

//��ȡ�汾�Ų�Ӳ����
BOOLEAN GetVersionAndHardCode() {
	BOOLEAN b = FALSE;
	switch (*NtBuildNumber) {
	case 7600:
	case 7601:
		ObjectCallbackListOffset = 0xC0;  //Win7
		b = TRUE;
		break;
	case 9200:
		ObjectCallbackListOffset = 0xC8;  //OBJECT_TYPE.CallbackList
		b = TRUE;
		break;
	case 9600:
		ObjectCallbackListOffset = 0xC8;  //OBJECT_TYPE.CallbackList
		b = TRUE;
		break;
	default:
		if (*NtBuildNumber > 10000) {
			ObjectCallbackListOffset = 0xc8;
			b = TRUE;
		}
		break;
	}
	return b;
}

//��ȡ�����еĵ��õ㴦����ת��ַ
PVOID GetCallPoint(PVOID pCallPoint)
{
	ULONG dwOffset = 0;  //��ʼ������ƫ��Ϊ0
	ULONG_PTR returnAddress = 0;  //��ʼ�����ص�ַΪ0
	LARGE_INTEGER returnAddressTemp = { 0 };  //��ʼ�����ص�ַ��ʱ����Ϊ0
	PUCHAR pFunAddress = NULL;  //��ʼ��������ַΪNULL

	if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))  //�������ĺ�����ַΪNULL���߲�����Ч��ַ���򷵻�NULL
		return NULL;

	pFunAddress = pCallPoint;  //������ĺ�����ַ��ֵ��������ַ����

	//�Ӻ�����ַ����һ���ֽڿ�ʼ������4�ֽ����ݵ�����ƫ�Ʊ���
	RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 1), sizeof(ULONG));

	//�ж��Ƿ�Ϊ������תָ�JMP��
	if ((dwOffset & 0x10000000) == 0x10000000)
	{
		//���޸Ĺ��Ĵ��� dwOffset = dwOffset + 5 + pFunAddress;  // ����ʵ�ʺ�����ַ
		dwOffset = dwOffset + 5 + *(ULONG*)pFunAddress;  // ����ʵ�ʺ�����ַ
		returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;  //��ȡ������ַ�ĸ�32λ
		returnAddressTemp.LowPart = dwOffset;  //��������ƫ�����õ���ʱ���ص�ַ�����ĵ�32λ
		returnAddress = returnAddressTemp.QuadPart;  //����ʱ���ص�ַ����ת��Ϊ���ص�ַ
		return (PVOID)returnAddress;  //���ؼ����ĺ�����ַ
	}
	//���޸Ĺ��Ĵ��� returnAddress = (ULONG_PTR)dwOffset + 5 + pFunAddress;  //����ʵ�ʺ�����ַ
	returnAddress = (ULONG_PTR)dwOffset + 5 + (ULONG_PTR)pFunAddress;  //����ʵ�ʺ�����ַ
	return (PVOID)returnAddress;  //���ؼ����ĺ�����ַ
}

//��ȡ�����е���ת��ַ
PVOID GetMovPoint(PVOID pCallPoint) //ָ����õ��ָ�룬���ڻ�ȡ��ת��ַ
{
	ULONG dwOffset = 0; //����ƫ��������ʼ��Ϊ 0
	ULONG_PTR returnAddress = 0; //���ص�ַ����ʼ��Ϊ 0
	LARGE_INTEGER returnAddressTemp = { 0 }; //��ʱ���ص�ַ�ṹ�壬ȫ����ʼ��Ϊ 0
	PUCHAR pFunAddress = NULL; //ָ������ַ��ָ�룬��ʼ��Ϊ NULL

	//�����õ��Ƿ�Ϊ NULL ���ߵ�ַ��Ч��������򷵻� NULL
	if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
		return NULL;

	pFunAddress = pCallPoint; //���ú�����ַָ��Ϊ���õ��ַ

	//���Ƶ��õ��ַ�� 3 �ֽڵ����ݵ� dwOffset������ȡ����ƫ����
	RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 3), sizeof(ULONG));

	//�ж��Ƿ�Ϊ JMP ������תָ��
	if ((dwOffset & 0x10000000) == 0x10000000)
	{
		//���޸ĵ�
		dwOffset = dwOffset + 7 + *(ULONG*)pFunAddress; //����ʵ��ƫ�Ƶ�ַ
		returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000; //��ȡ������ַ�ĸ� 32 λ
		returnAddressTemp.LowPart = dwOffset; //���ú�����ַ�ĵ� 32 λΪƫ�Ƶ�ַ
		returnAddress = returnAddressTemp.QuadPart; //�ϲ��ߵ�λ�õ����ص�ַ
		return (PVOID)returnAddress; //���غ����е���ת��ַ
	}

	returnAddress = (ULONG_PTR)dwOffset + 7 + (ULONG_PTR)pFunAddress; //����ʵ��ƫ�Ƶ�ַ
	return (PVOID)returnAddress; //���غ����е���ת��ַ
}

//��ȡPsLoadedModuleList��ַ�������жϵ�ַ����ģ��
PVOID GetPsLoadedListModule()
{
	UNICODE_STRING usRtlPcToFileHeader = RTL_CONSTANT_STRING(L"RtlPcToFileHeader"); //ָ���ַ��� "RtlPcToFileHeader"
	UNICODE_STRING usPsLoadedModuleList = RTL_CONSTANT_STRING(L"PsLoadedModuleList"); //ָ���ַ��� "PsLoadedModuleList"
	PVOID Point = NULL; //ָ���ڴ��ַ��ָ�룬��ʼ��Ϊ NULL
	static PVOID PsLoadedListModule = NULL; //��ָ̬���ڴ��ַ��ָ�룬��ʼ��Ϊ NULL
	UCHAR shellcode[11] = "\x48\x8b\x0d\x60\x60\x60\x60" "\x48\x85\xc9"; //���ڶ�λ������������

	//��� PsLoadedListModule ��Ϊ�գ�ֱ�ӷ��� PsLoadedListModule
	if (PsLoadedListModule)
		return PsLoadedListModule;

	//�������ϵͳ�汾���� 9600��Win10������ȡ PsLoadedModuleList ģ���ַ������
	if (*NtBuildNumber > 9600)
	{
		PsLoadedListModule = MmGetSystemRoutineAddress(&usPsLoadedModuleList); //��ȡ PsLoadedModuleList ģ���ַ
		return PsLoadedListModule;
	}

	//��ȡ PsLoadedModuleList ģ���ַ��Win7��
	Point = GetUndocumentFunctionAddress(&usRtlPcToFileHeader, NULL, shellcode, 10, 0xff, 0x60, 0, TRUE);
	if (Point == NULL || !MmIsAddressValid(Point))
		return NULL;
	Point = GetMovPoint(Point);
	if (Point == NULL || !MmIsAddressValid(Point))
		return NULL;
	PsLoadedListModule = Point;
	return PsLoadedListModule;
}

//���ݵ�ַ �ж���������ģ��
BOOLEAN ObGetDriverNameByPoint(ULONG_PTR Point, OUT WCHAR* szDriverName)
{
	PLDR_DATA_TABLE_ENTRY Begin = NULL; //ָ����ص�ģ��� LDR_DATA_TABLE_ENTRY �ṹ��ָ�룬��ʼ��Ϊ NULL
	PLIST_ENTRY Head = NULL; //ָ������ͷ����ָ�룬��ʼ��Ϊ NULL
	PLIST_ENTRY Next = NULL; //ָ��������һ��Ԫ�ص�ָ�룬��ʼ��Ϊ NULL

	//��ȡ PsLoadedModuleList ��ͷ���ڵ�
	Begin = GetPsLoadedListModule();
	if (Begin == NULL)
		return FALSE; //�����ȡʧ�ܣ����� FALSE

	//��ȡ����ͷ������һ��Ԫ�ص�ָ��
	Head = (PLIST_ENTRY)Begin->InLoadOrderLinks.Flink;
	Next = Head->Flink;

	//��ʼѭ����������
	do
	{
		//�� Next ָ��ת��Ϊ LDR_DATA_TABLE_ENTRY �ṹ��ָ��
		PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		Next = Next->Flink; //ָ����һ���ڵ�

		//�жϸ����ĵ�ַ Point �Ƿ���ģ���ַ��Χ��
		if ((ULONG_PTR)Entry->DllBase <= Point && Point <= ((ULONG_PTR)Entry->DllBase + Entry->SizeOfImage))
		{
			if (szDriverName == NULL)
				return FALSE; //�������� szDriverName Ϊ NULL������ FALSE

			//��� szDriverName ���ڴ�
			RtlZeroMemory(szDriverName, 600);
			//����ģ�����Ƶ� szDriverName ��
			RtlCopyMemory(szDriverName, Entry->BaseDllName.Buffer, Entry->BaseDllName.Length);
			return TRUE; //�����ҵ�������������
		}
	} while (Next != Head->Flink); //ѭ������ֱ����һ��ָ���ٴ�ָ���׽�㣬���������

	return FALSE; //���û���ҵ�ƥ��������������ƣ����� FALSE
}

//�������лص�����
ULONG EnumObRegisterCallBacks()
{
	ULONG c = 0;  //�ص��ۼӼ���
	PLIST_ENTRY CurrEntry = NULL;  //��ǰ������������ָ��
	POB_CALLBACK pObCallback;  //ָ��ص��ṹ��ָ��
	ULONG64 ObProcessCallbackListHead = 0;  //���̻ص��б�ͷ
	ULONG64 ObThreadCallbackListHead = 0;  //�̻߳ص��б�ͷ
	PVOID szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);  //���������������

	//�����ڴ����������������� //���޸�
	//szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);
	//szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);

	if (szDriverBaseName == NULL)
		return 0;  //����ʧ���򷵻�

	//�����������������Ƶ��ڴ�
	RtlZeroMemory(szDriverBaseName, 600);
	GetVersionAndHardCode();  //��ȡ�汾��Ϣ��Ӳ����

	//������̻ص��б�ͷ���̻߳ص��б�ͷ�ĵ�ַ
	ObProcessCallbackListHead = *(ULONG64*)PsProcessType + ObjectCallbackListOffset;
	ObThreadCallbackListHead = *(ULONG64*)PsThreadType + ObjectCallbackListOffset;

	//���������Ϣ
	KdPrint(("������SYS->������ʼ+++++++++++++++++++++++++++++++++++++++++>\n"));

	//�������̻ص��б�
	KdPrint(("������SYS ���̻ص�������ʼ-----------------------------��:\n"));
	CurrEntry = ((PLIST_ENTRY)ObProcessCallbackListHead)->Flink;
	if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
	{
		ExFreePool(szDriverBaseName);  //�ͷ��ڴ�
		return 0;  //����0
	}
	do
	{
		//��ȡ��ǰ�ص���
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			//����ص�����Ч�����ȡ�����������Ʋ����������Ϣ
			if (ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
				DbgPrint("������SYS>DriverName=%S ObHandle=%p Index=%wZ PreCall=%p PostCall=%p \n",
					szDriverBaseName,
					pObCallback->ObHandle,
					&pObCallback->ObHandle->AltitudeString,
					pObCallback->PreCall,
					pObCallback->PostCall);
			c++;  //��������1
		}
		CurrEntry = CurrEntry->Flink;  //ָ����һ��������
	} while (CurrEntry != (PLIST_ENTRY)ObProcessCallbackListHead);  //��ǰ����ڽ��̻ص��б�ͷʱ��������

	//���������Ϣ
	KdPrint(("������SYS ���̻ص���������-----------------------------��:\n"));

	//�����̻߳ص��б�
	DbgPrint("������SYS->�̶߳���ص� ������ʼ------------------->:\n");
	CurrEntry = ((PLIST_ENTRY)ObThreadCallbackListHead)->Flink;
	if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
	{
		ExFreePool(szDriverBaseName);  //�ͷ��ڴ�
		return c;  //���ؼ�����ֵ
	}
	do
	{
		//��ȡ��ǰ�ص���
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			//����ص�����Ч�����ȡ�����������Ʋ����������Ϣ
			if (ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
				DbgPrint("������SYS>DriverName=%S ObHandle=%p Index=%wZ PreCall=%p PostCall=%p \n",
					szDriverBaseName,
					pObCallback->ObHandle,
					&pObCallback->ObHandle->AltitudeString,
					pObCallback->PreCall,
					pObCallback->PostCall);
			c++;  //��������1
		}
		CurrEntry = CurrEntry->Flink;  //ָ����һ��������
	} while (CurrEntry != (PLIST_ENTRY)ObThreadCallbackListHead);  //��ǰ������̻߳ص��б�ͷʱ��������

	//���������Ϣ�ͼ�����ֵ
	DbgPrint("������SYS->�̶߳���ص� ��������------------------->:\n");
	DbgPrint("������SYS ע��ص�������: %ld\n", c);

	ExFreePool(szDriverBaseName);  //�ͷ��ڴ�
	KdPrint(("������SYS->��������+++++++++++++++++++++++++++++++++++++++++>\n"));
	return c;  //���ؼ�����ֵ
}

//��ȡ����ص��ĸ߶��ַ�����������������Ƿ�ƥ�䡣
BOOLEAN ObGetCallBacksAltitude2(WCHAR* szDriverName, PUNICODE_STRING usAltitudeString, BOOLEAN bGetProcess)
{
	BOOLEAN bRet = FALSE;  //��ʼ������ֵΪFALSE
	PLIST_ENTRY CurrEntry = NULL;  //��ʼ������ǰ�ڵ�ΪNULL
	POB_CALLBACK pObCallback;  //�������ص��ṹ��ָ��
	ULONG_PTR ObCallbackListHead = 0;  //��ʼ������ص��б�ͷ��ַΪ0
	//PVOID szDriverBaseName = NULL;  //��ʼ��������������ָ��ΪNULL

	GetVersionAndHardCode();  //��ȡ�汾��Ӳ������Ϣ

	//���ݲ���ѡ�����ص��б�ͷ��ַ
	if (bGetProcess)
		ObCallbackListHead = *(ULONG_PTR*)PsProcessType + ObjectCallbackListOffset;
	else
		ObCallbackListHead = *(ULONG_PTR*)PsThreadType + ObjectCallbackListOffset;

	CurrEntry = ((PLIST_ENTRY)ObCallbackListHead)->Flink;  //��ȡ����ǰ�ڵ�ָ��

	//�����ǰ�ڵ�Ϊ�ջ��߲�����Ч��ַ���򷵻�FALSE
	if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
		return bRet;

	//���������ַ���ָ��Ϊ�գ�����Unicode�ַ���ָ��Ϊ�գ�����Unicode�ַ����Ļ�����Ϊ�գ��򷵻�FALSE
	if (szDriverName == NULL || usAltitudeString == NULL || usAltitudeString->Buffer == NULL)
		return FALSE;

	PVOID szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);  //�����ڴ�����������������

	//��������ڴ�ʧ�ܣ��򷵻�FALSE
	if (szDriverBaseName == NULL)
		return FALSE;

	RtlZeroMemory(szDriverBaseName, 600);  //��������ڴ�����

	do
	{
		pObCallback = (POB_CALLBACK)CurrEntry;  //��ȡ��ǰ�ڵ��Ӧ�Ķ���ص��ṹ��ָ��

		if (pObCallback->ObHandle != 0)  //�����������Ϊ0
		{
			DbgPrint("������SYSObHandle: %p\n", pObCallback->ObHandle);  //��ӡ������
			DbgPrint("������SYSIndex: %wZ\n", &pObCallback->ObHandle->AltitudeString);  //��ӡ�������ĸ߶��ַ���
			DbgPrint("������SYSPreCall: %lld\n", pObCallback->PreCall);  //��ӡԤ���ú�����ַ
			DbgPrint("������SYSPostCall: %lld\n", pObCallback->PostCall);  //��ӡ����ú�����ַ

			//�����ȡ��������ʧ�ܣ�������ѭ��
			if (!ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
				break;

			DbgPrint("������SYSDriverName: %p\n", szDriverBaseName);  //��ӡ��ȡ������������

			//�������������������ȡ������������ƥ��
			if (!_wcsnicmp(szDriverBaseName, szDriverName, wcslen(szDriverName) * 2))
			{
				bRet = TRUE;  //���÷���ֵΪTRUE
				RtlCopyMemory(usAltitudeString->Buffer, pObCallback->ObHandle->AltitudeString.Buffer, pObCallback->ObHandle->AltitudeString.Length);  //���Ƹ߶��ַ�����Unicode�ַ���������
				usAltitudeString->Length = pObCallback->ObHandle->AltitudeString.Length;  //����Unicode�ַ�������
				usAltitudeString->MaximumLength = 600;  //����Unicode�ַ�����󳤶�
				break;  //����ѭ��
			}
		}

		CurrEntry = CurrEntry->Flink;  //����ǰ�ڵ�ָ���ƶ�����һ���ڵ�
	} while (CurrEntry != (PLIST_ENTRY)ObCallbackListHead);  //ѭ��ֱ����ǰ�ڵ�ָ��ָ�����ص��б�ͷ

	ExFreePool(szDriverBaseName);  //�ͷŷ�����ڴ�
	return bRet;  //���ؽ��
}

//��ȡδ�ĵ����ĺ�����ַ
PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, //ָ�� Unicode �ַ����ṹ��ָ�룬����ָ����������
	IN PUCHAR pStartAddress, //ָ������ʼ��ַ��ָ�룬����ָ����������ʼ��ַ
	IN UCHAR* pFeatureCode, //ָ�������������ָ�룬����ָ��Ҫƥ�������������
	IN ULONG FeatureCodeNum, //����������������ָ�����������еĳ���
	ULONG SerSize, //���д�С������ָ��Ҫ���������еĳ���
	UCHAR SegCode, //�ָ��룬����ָ�������������еķָ����
	ULONG AddNum, //ƫ����������ָ�����ص�ַ��ƫ����
	BOOLEAN ByName) //����ֵ��ָʾ�Ƿ�ͨ���������ƻ�ȡ��ַ
{
	ULONG dwIndex = 0; //ѭ������������ʼ��Ϊ 0
	PUCHAR pFunAddress = NULL; //ָ������ַ��ָ�룬��ʼ��Ϊ NULL
	ULONG dwCodeNum = 0; //������ƥ�����������ʼ��Ϊ 0

	//��������������Ƿ�Ϊ NULL��������򷵻� NULL
	if (pFeatureCode == NULL)
		return NULL;
	//��������������Ƿ���ڵ��� 15��������򷵻� NULL
	if (FeatureCodeNum >= 15)
		return NULL;
	//������д�С�Ƿ���� 0x1024��������򷵻� NULL
	if (SerSize > 0x1024)
		return NULL;

	//���� ByName ��ֵȷ����ȡ������ַ�ķ�ʽ
	if (ByName)
	{
		//��� ByName Ϊ TRUE����ͨ���������ƻ�ȡ��ַ
		if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
			return NULL; //��麯�������Ƿ���Ч�������Ч�򷵻� NULL
		pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName); //��ȡ������ַ
		if (pFunAddress == NULL)
			return NULL; //�����ȡʧ�ܣ����� NULL
	}
	else
	{
		//��� ByName Ϊ FALSE����ʹ�ô���ĺ�����ʼ��ַ
		if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
			return NULL; //��麯����ʼ��ַ�Ƿ���Ч�������Ч�򷵻� NULL
		pFunAddress = pStartAddress; //ʹ�ô���ĺ�����ʼ��ַ
	}

	//ѭ���������н���������ƥ��
	for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
	{
		__try
		{
			//����������Ƿ�ƥ����ߵ��ڷָ���
			if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] || pFeatureCode[dwCodeNum] == SegCode)
			{
				dwCodeNum++; //������ƥ���������һ
				if (dwCodeNum == FeatureCodeNum)
					//���������ƥ���������������������������ƥ�䵽�ĺ�����ַ����ƫ����
					return pFunAddress + dwIndex - dwCodeNum + 1 + AddNum;
				continue; //����ƥ����һ��������
			}
			dwCodeNum = 0; //�����ƥ�䣬��������ƥ�����������
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0; //��������쳣������ 0
		}
	}

	return 0; //����������������ж�û��ƥ�䵽���������У����� 0
}