#include <ntifs.h>
//#include "inject\ssdt.h"
#include "inject\undocumented.h"
#include "inject\ntdll.h"

//�ر�����
//ExAllocatePoolZero
//�������ֻ����windows�Ͱ汾ʹ�ã����µ�����ExAllocatePool2

//ExFreeToNPagedLookasideList  
//��Windows11 �汾 22H2 ��ʼ���˺�������������Ϊ������ ��ˣ���������������°汾�� Windows ���������򣬽��޷��ڽϾɵ� OS �汾�м��ظ��������� ��Ҫ�� Visual Studio �и���Ŀ�� OS �汾����ѡ���������ԡ�->�������������á�->�����桱��
//��������汾ΪWindows 10 Kernel Version 17763 MP (1 procs) Free x64 ������ѡ����Windows 10.0.17763


#define д���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define ������ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define ��д���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_����ܱ�����PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ɾ���ܱ�����PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_����ܱ�����PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_д���ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_��ȡ�ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define CTL_IO_�����ڴ�д�� CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����
#define CTL_IO_�����ڴ��ȡ CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����

#define IO_�������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ɾ������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_�������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_ͨ�������ȡ���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ͨ�����̱������ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_ZwQueryVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define TAG_INJECTLIST	'ljni'
#define TAG_INJECTDATA	'djni'

extern "C"
NTKERNELAPI
PVOID NTAPI PsGetProcessWow64Process(PEPROCESS process);

extern "C"
NTKERNELAPI
NTSTATUS NTAPI PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS * Process
);

//
//ע���б�ṹ��
//
typedef NTSTATUS(NTAPI* fn_NtAllocateVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
	);
typedef NTSTATUS(NTAPI* fn_NtReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);
typedef NTSTATUS(NTAPI* fn_NtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ CONST VOID* Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* fn_NtProtectVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);


typedef struct _INJECT_PROCESSID_LIST {			//ע���б���Ϣ
	LIST_ENTRY	link;
	HANDLE pid;
	BOOLEAN	inject;
}INJECT_PROCESSID_LIST, * PINJECT_PROCESSID_LIST;

typedef struct _INJECT_PROCESSID_DATA {			//ע�����������Ϣ
	HANDLE	pid;
	PVOID	imagebase;
	SIZE_T	imagesize;
}INJECT_PROCESSID_DATA, * PINJECT_PROCESSID_DATA;

typedef struct _INJECT_PROCESSID_DLL {			//�ڴ����DLL��Ϣ
	PVOID	x64dll;
	ULONG	x64dllsize;
	PVOID	x86dll;
	ULONG	x86dllsize;
}INJECT_PROCESSID_DLL, * PINJECT_PROCESSID_DLL;

#pragma pack(push,1)

//
//x86 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X86 {
	UCHAR	saveReg[2]; //pushad //pushfd
	UCHAR	restoneHook[17]; // mov esi,5 mov edi,123 mov esi,456 rep movs byte
	UCHAR	invokeMemLoad[10]; // push xxxxxx call xxxxxx
	UCHAR	eraseDll[14]; // mov al,0 mov ecx,len mov edi,addr rep stos
	UCHAR	restoneReg[2];//popfd popad
	UCHAR	jmpOld[5]; //jmp

	UCHAR	oldData[5];

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X86, * PINJECT_PROCESSID_PAYLOAD_X86;

//
// x64 payload
//
typedef struct _INJECT_PROCESSID_PAYLOAD_X64 {
	UCHAR	saveReg[25];
	UCHAR	subStack[4];
	UCHAR	restoneHook[32]; // mov rcx,xxxx mov rdi,xxxx mov rsi,xxx rep movs byte
	UCHAR	invokeMemLoad[15]; // mov rcx,xxxxx call xxxx
	UCHAR	eraseDll[24]; // mov rdi,xxxx xor eax,eax mov rcx,xxxxx rep stosb
	UCHAR	addStack[4];
	UCHAR	restoneReg[27];
	UCHAR	jmpOld[14]; //jmp qword [0]

	UCHAR	oldData[14];//

	UCHAR	dll[1];
	UCHAR	shellcode[1];

}INJECT_PROCESSID_PAYLOAD_X64, * PINJECT_PROCESSID_PAYLOAD_X64;

#pragma pack(pop)

//
//ȫ�ֽ�������
//
INJECT_PROCESSID_LIST	g_injectList;
INJECT_PROCESSID_DLL	g_injectDll;
ERESOURCE			g_ResourceMutex;
NPAGED_LOOKASIDE_LIST g_injectListLookaside;
NPAGED_LOOKASIDE_LIST g_injectDataLookaside;
fn_NtAllocateVirtualMemory	pfn_NtAllocateVirtualMemory;
fn_NtReadVirtualMemory		pfn_NtReadVirtualMemory;
fn_NtWriteVirtualMemory		pfn_NtWriteVirtualMemory;
fn_NtProtectVirtualMemory	pfn_NtProtectVirtualMemory;

//���������豸����
#define ���������� L"\\??\\HookDriver"

//�����豸
NTSTATUS CreateDevice(PDRIVER_OBJECT driver)
{
	NTSTATUS status;
	UNICODE_STRING MyDriver;
	PDEVICE_OBJECT device;//���ڴ���豸����
	RtlInitUnicodeString(&MyDriver, L"\\DEVICE\\MyDriver");//�����豸����
	status = IoCreateDevice(driver,
		sizeof(driver->DriverExtension),
		&MyDriver,
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);

	if (status == STATUS_SUCCESS)//STATUS_SUCCESS)
	{
		KdPrint(("�����豸���󴴽��ɹ�,OK \n"));//������������
		UNICODE_STRING uzSymbolName; //������������
		RtlInitUnicodeString(&uzSymbolName, ����������); //CreateFile
		status = IoCreateSymbolicLink(&uzSymbolName, &MyDriver);
		if (status == STATUS_SUCCESS)
		{
			KdPrint(("���������������� %wZ �ɹ�", &uzSymbolName));
		}
		else {
			KdPrint(("���������������� %wZ ʧ�� status=%X", &uzSymbolName, status));
		}
	}
	else {
		KdPrint(("�����豸���󴴽�ʧ�ܣ�ɾ���豸"));
		if (device == NULL)	//�޸������жϽ�����־���Warning C6387
			return status;	//���if������������return �����Ч����0���ظ�������������ǰ�����˳���
		IoDeleteDevice(device);
	}
	return status;
}

//ɾ���豸
void DeleteDriver(PDRIVER_OBJECT pDriver)
{
	KdPrint(("����������ж������"));
	if (pDriver->DeviceObject)
	{

		//ɾ����������
		UNICODE_STRING uzSymbolName;//������������
		RtlInitUnicodeString(&uzSymbolName, ����������); //CreateFile
		KdPrint(("����ɾ����������=%wZ", &uzSymbolName));
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		KdPrint(("����ɾ�������豸"));
		IoDeleteDevice(pDriver->DeviceObject);//ɾ���豸����
	}
	KdPrint(("�����˳�ж������"));
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {

	//PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
	//PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	UNREFERENCED_PARAMETER(DriverObject);
	//ɾ����������
	DeleteDriver(DriverObject);
	KdPrint(("����ж��\n"));

	if (g_injectDll.x64dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x64dll, 'd64x');
	}
	if (g_injectDll.x86dll != NULL)
	{
		ExFreePoolWithTag(g_injectDll.x86dll, 'd68x');
	}

	while (!IsListEmpty(&g_injectList.link))
	{
		PINJECT_PROCESSID_LIST next = (PINJECT_PROCESSID_LIST)g_injectList.link.Blink;
		RemoveEntryList(&next->link);
		ExFreeToNPagedLookasideList(&g_injectListLookaside, &next->link);
	}

	if (&g_ResourceMutex != NULL)
		ExDeleteResourceLite(&g_ResourceMutex);
	if (&g_injectListLookaside != NULL)
		ExDeleteNPagedLookasideList(&g_injectListLookaside);
	if (&g_injectDataLookaside != NULL)
		ExDeleteNPagedLookasideList(&g_injectDataLookaside);
}

NTSTATUS IRP_CALL(PDEVICE_OBJECT DriverObject, PIRP pirp) {

	UNREFERENCED_PARAMETER(DriverObject);//һ����Ч��
	KdPrint(("������ǲ��������\n"));
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	switch (irpStackL->MajorFunction) {
	case IRP_MJ_DEVICE_CONTROL:
	{
		if (irpStackL == NULL) {
			//�������
			return STATUS_INVALID_PARAMETER;
		}
		ULONG ������;
		������ = irpStackL->Parameters.DeviceIoControl.IoControlCode;
		switch (������) {
		case IO_��ȡ�ܱ����Ľ���:
			break;
			//case IO_д���ܱ����Ľ���:
			//	return IRP_WriteProcessMemory2(pirp);
			//case CTL_IO_�����ڴ��ȡ:
			//	return IRP_ReadPVirtualMemory(pirp);
			//case CTL_IO_�����ڴ�д��:
			//	return IRP_WritePVirtualMemory(pirp);
			//case IO_ͨ�������ȡ����:
			//	return IRP_ͨ�������ȡ����(pirp);
			//case IO_ͨ�����̱������:
			//	return IRP_ͨ�����̱������(pirp);
		case IO_ZwQueryVirtualMemory:
			break;
		}
	}
	case IRP_MJ_CREATE:
	{
		KdPrint(("������ǲ����IRP_MJ_CREATE\n"));
	}
	case IRP_MJ_CLOSE:
	{
		KdPrint(("������ǲ����IRP_MJ_CLOSE\n"));
	}
	default:
		break;
	}

	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 4;//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	KdPrint(("������ǲ�����뿪"));
	return STATUS_SUCCESS;
}

NTSTATUS DriverControlHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)

{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PUCHAR				inBuf, outBuf;
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);

	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_SET_INJECT_X86DLL:
	{
		if (g_injectDll.x86dll == NULL && g_injectDll.x86dllsize == 0)
		{
			////�����޸�
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x86dll = ExAllocatePoolZero(NonPagedPool, inBufLength, 'd68x');
			if (g_injectDll.x86dll != NULL)
			{
				g_injectDll.x86dllsize = inBufLength;
				memcpy(g_injectDll.x86dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
		break;
	}
	case IOCTL_SET_INJECT_X64DLL:
	{
		if (g_injectDll.x64dll == NULL && g_injectDll.x64dllsize == 0)
		{
			////�����޸�
			PIMAGE_DOS_HEADER dosHeadPtr = (PIMAGE_DOS_HEADER)inBuf;
			if (dosHeadPtr->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			g_injectDll.x64dll = ExAllocatePoolZero(NonPagedPool, inBufLength, 'd64x');
			if (g_injectDll.x64dll != NULL)
			{
				g_injectDll.x64dllsize = inBufLength;
				memcpy(g_injectDll.x64dll, inBuf, inBufLength);
				ntStatus = STATUS_SUCCESS;
			}
		}
		break;
	}

	default:
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	__debugbreak();

	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("������װ\n"));
	//����ж������
	DriverObject->DriverUnload = DriverUnload;
	//������ǲ����
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_CALL;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlHandler;

	//read ntdll.dll from disk so we can use it for exports
	//if (!NT_SUCCESS(NTDLL::Initialize()))
	//{
	//	DPRINT("[DeugMessage] Ntdll::Initialize() failed...\r\n");
	//	return STATUS_UNSUCCESSFUL;
	//}

	//��ʼ������ҪNT��ZW�����ĵ�ַ������ָ���Լ�����ı���
	if (!Undocumented::UndocumentedInit())
	{
		DPRINT("[DeugMessage] UndocumentedInit() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//������������
	CreateDevice(DriverObject);

	InitializeListHead((PLIST_ENTRY)&g_injectList);
	ExInitializeResourceLite(&g_ResourceMutex);
	ExInitializeNPagedLookasideList(&g_injectListLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_LIST), TAG_INJECTLIST, NULL);
	ExInitializeNPagedLookasideList(&g_injectDataLookaside, NULL, NULL, NULL, sizeof(INJECT_PROCESSID_DATA), TAG_INJECTDATA, NULL);
	memset(&g_injectDll, 0, sizeof(INJECT_PROCESSID_DLL));



	//pfn_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)SSDT::GetFunctionAddress("NtAllocateVirtualMemory");
	//pfn_NtReadVirtualMemory = (fn_NtReadVirtualMemory)SSDT::GetFunctionAddress("NtReadVirtualMemory");
	//pfn_NtWriteVirtualMemory = (fn_NtWriteVirtualMemory)SSDT::GetFunctionAddress("NtWriteVirtualMemory");
	//pfn_NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)SSDT::GetFunctionAddress("NtProtectVirtualMemory");
	//if (pfn_NtAllocateVirtualMemory == NULL ||
	//	pfn_NtReadVirtualMemory == NULL ||
	//	pfn_NtWriteVirtualMemory == NULL ||
	//	pfn_NtProtectVirtualMemory == NULL)
	//{
	//	//NTDLL::Deinitialize();
	//	//IoDeleteSymbolicLink(&Win32Device);
	//	//IoDeleteDevice(DriverObject->DeviceObject);
	//	//return STATUS_UNSUCCESSFUL;
	//}

	return STATUS_SUCCESS;
}

