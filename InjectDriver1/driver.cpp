#include <ntifs.h>
//#include "inject\ssdt.h"
#include "inject\undocumented.h"
#include "inject\ntdll.h"

//特别提醒
//ExAllocatePoolZero
//这个函数只能在windows低版本使用，最新的请用ExAllocatePool2

//ExFreeToNPagedLookasideList  
//从Windows11 版本 22H2 开始，此函数从内联更改为导出。 因此，如果生成面向最新版本的 Windows 的驱动程序，将无法在较旧的 OS 版本中加载该驱动程序。 若要在 Visual Studio 中更改目标 OS 版本，请选择“配置属性”->“驱动程序设置”->“常规”。
//我虚拟机版本为Windows 10 Kernel Version 17763 MP (1 procs) Free x64 ，所以选择了Windows 10.0.17763


#define 写测试 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define 读测试 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define 读写测试 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_添加受保护的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_删除受保护的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_清空受保护的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_写入受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_读取受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define CTL_IO_物理内存写入 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试
#define CTL_IO_物理内存读取 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试

#define IO_添加需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_删除需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_清空需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_通过句柄获取对象 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_通过进程遍历句柄 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_ZwQueryVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

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
//注入列表结构体
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


typedef struct _INJECT_PROCESSID_LIST {			//注入列表信息
	LIST_ENTRY	link;
	HANDLE pid;
	BOOLEAN	inject;
}INJECT_PROCESSID_LIST, * PINJECT_PROCESSID_LIST;

typedef struct _INJECT_PROCESSID_DATA {			//注入进程数据信息
	HANDLE	pid;
	PVOID	imagebase;
	SIZE_T	imagesize;
}INJECT_PROCESSID_DATA, * PINJECT_PROCESSID_DATA;

typedef struct _INJECT_PROCESSID_DLL {			//内存加载DLL信息
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
//全局进程链表
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

//创建驱动设备对象
#define 符号链接名 L"\\??\\HookDriver"

//创建设备
NTSTATUS CreateDevice(PDRIVER_OBJECT driver)
{
	NTSTATUS status;
	UNICODE_STRING MyDriver;
	PDEVICE_OBJECT device;//用于存放设备对象
	RtlInitUnicodeString(&MyDriver, L"\\DEVICE\\MyDriver");//驱动设备名字
	status = IoCreateDevice(driver,
		sizeof(driver->DriverExtension),
		&MyDriver,
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);

	if (status == STATUS_SUCCESS)//STATUS_SUCCESS)
	{
		KdPrint(("驱动设备对象创建成功,OK \n"));//创建符号链接
		UNICODE_STRING uzSymbolName; //符号链接名字
		RtlInitUnicodeString(&uzSymbolName, 符号链接名); //CreateFile
		status = IoCreateSymbolicLink(&uzSymbolName, &MyDriver);
		if (status == STATUS_SUCCESS)
		{
			KdPrint(("驱动创建符号链接 %wZ 成功", &uzSymbolName));
		}
		else {
			KdPrint(("驱动创建符号链接 %wZ 失败 status=%X", &uzSymbolName, status));
		}
	}
	else {
		KdPrint(("驱动设备对象创建失败，删除设备"));
		if (device == NULL)	//无该条件判断将会出现警告Warning C6387
			return status;	//如果if条件成立，则return 语句生效，把0返回给主函数，即提前结束了程序
		IoDeleteDevice(device);
	}
	return status;
}

//删除设备
void DeleteDriver(PDRIVER_OBJECT pDriver)
{
	KdPrint(("驱动进入了卸载例程"));
	if (pDriver->DeviceObject)
	{

		//删除符号链接
		UNICODE_STRING uzSymbolName;//符号链接名字
		RtlInitUnicodeString(&uzSymbolName, 符号链接名); //CreateFile
		KdPrint(("驱动删除符号链接=%wZ", &uzSymbolName));
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		KdPrint(("驱动删除驱动设备"));
		IoDeleteDevice(pDriver->DeviceObject);//删除设备对象
	}
	KdPrint(("驱动退出卸载例程"));
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {

	//PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);
	//PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	UNREFERENCED_PARAMETER(DriverObject);
	//删除驱动对象
	DeleteDriver(DriverObject);
	KdPrint(("驱动卸载\n"));

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

	UNREFERENCED_PARAMETER(DriverObject);//一个无效宏
	KdPrint(("驱动派遣函数进入\n"));
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	switch (irpStackL->MajorFunction) {
	case IRP_MJ_DEVICE_CONTROL:
	{
		if (irpStackL == NULL) {
			//处理错误
			return STATUS_INVALID_PARAMETER;
		}
		ULONG 控制码;
		控制码 = irpStackL->Parameters.DeviceIoControl.IoControlCode;
		switch (控制码) {
		case IO_读取受保护的进程:
			break;
			//case IO_写入受保护的进程:
			//	return IRP_WriteProcessMemory2(pirp);
			//case CTL_IO_物理内存读取:
			//	return IRP_ReadPVirtualMemory(pirp);
			//case CTL_IO_物理内存写入:
			//	return IRP_WritePVirtualMemory(pirp);
			//case IO_通过句柄获取对象:
			//	return IRP_通过句柄获取对象(pirp);
			//case IO_通过进程遍历句柄:
			//	return IRP_通过进程遍历句柄(pirp);
		case IO_ZwQueryVirtualMemory:
			break;
		}
	}
	case IRP_MJ_CREATE:
	{
		KdPrint(("驱动派遣调用IRP_MJ_CREATE\n"));
	}
	case IRP_MJ_CLOSE:
	{
		KdPrint(("驱动派遣调用IRP_MJ_CLOSE\n"));
	}
	default:
		break;
	}

	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 4;//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	KdPrint(("驱动派遣函数离开"));
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
			////周腾修改
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
			////周腾修改
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
	KdPrint(("驱动安装\n"));
	//设置卸载例程
	DriverObject->DriverUnload = DriverUnload;
	//设置派遣函数
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

	//初始化所需要NT，ZW方法的地址，将它指向自己定义的变量
	if (!Undocumented::UndocumentedInit())
	{
		DPRINT("[DeugMessage] UndocumentedInit() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	//创建驱动对象
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

