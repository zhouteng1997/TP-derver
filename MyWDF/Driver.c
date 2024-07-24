#include <ntddk.h>
#include "Driver.h"

#include "LinkDevice.h"
#include "进程保护.h" //包含自定义的头文件 "进程保护.h"
#include "远程读写内存驱动.h" //包含自定义的头文件 "进程保护.h"
#include "通过物理地址读写进程内存.h"
#include "遍历对象回调钩子.h"
#include "过掉对象钩子保护.h"
#include "通过句柄获取对象.h"
#include "遍历进程的句柄.h"


//r3常用函数
//WriteProcessMemory写内存
//ReadProcessMemory 读内存
//结束进程
//TerminateProcess
//VirtualProtectEx修改页而属性
//VirtualAllocEx VirtualFreeEx
//CreateRemoteThread 片cal1
//DuplicateHandle 复制柄

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

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	//卸载进程保护
	卸载进程保护();
	//卸载回调钩子
	ObRegisterUnload();
	//删除驱动对象
	DeleteDriver(DriverObject);
	KdPrint(("驱动卸载\n"));
}
NTSTATUS IRP_IO_写测试(PIRP pirp) {
	/*char* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	KdPrint(("驱动派遣调用IRP_MJ_DEVICE_CONTROL   控制码为 %X  缓冲区: %s \n", 写测试, 缓冲区));*/
	UNREFERENCED_PARAMETER(pirp);
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_读测试(PIRP pirp) {
	char* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	//写入缓冲区
	char 返回字符串[] = "123456";
	memcpy_s(缓冲区, sizeof(返回字符串), 返回字符串, sizeof(返回字符串));
	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = sizeof(返回字符串);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_读写测试(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	int* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区) {
		int* p = (int*)缓冲区;
		int 结果 = p[0] + p[1] + p[2];
		*(int*)缓冲区 = 结果;
		KdPrint(("驱动结果为 %d\n", 结果));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_添加受保护的PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	int* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区) {
		UINT64* pPID = (UINT64*)缓冲区;
		UINT64 pid = pPID[0];
		添加受保护的PID(pid);
		KdPrint(("驱动 添加受保护的PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	}
	return STATUS_SUCCESS;
}

NTSTATUS IRP_IO_删除受保护的PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	int* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区) {
		UINT64* pPID = (UINT64*)缓冲区;
		UINT64 pid = pPID[0];
		删除受保护的PID(pid);
		KdPrint(("驱动 删除受保护的PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_清空受保护的PID(PIRP pirp) {
	pirp;
	清空受保护数组();
	return STATUS_SUCCESS;
}


NTSTATUS IRP_IO_添加需提权的PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	int* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区) {
		UINT64* pPID = (UINT64*)缓冲区;
		UINT64 pid = pPID[0];
		添加需提权的PID(pid);
		KdPrint(("驱动 添加需提权的PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_删除需提权的PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	int* 缓冲区 = pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区) {
		UINT64* pPID = (UINT64*)缓冲区;
		UINT64 pid = pPID[0];
		删除需提权的PID(pid);
		KdPrint(("驱动 删除需提权的PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_清空需提权的PID(PIRP pirp) {
	pirp;
	清空需提权数组();
	return STATUS_SUCCESS;
}

NTSTATUS IRP_CALL(PDEVICE_OBJECT DriverObject, PIRP pirp) {

	UNREFERENCED_PARAMETER(DriverObject);//一个无效宏
	KdPrint(("驱动派遣函数进入\n"));
	PIO_STACK_LOCATION irpStackL;
	//ULONG CrlCode;
	//ULONG InputBuffLength;

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
		case 写测试:
			return IRP_IO_写测试(pirp);
		case 读测试:
			return IRP_IO_读测试(pirp);
		case 读写测试:
			return IRP_IO_读写测试(pirp);
		case IO_添加受保护的PID:
			return IRP_IO_添加受保护的PID(pirp);
		case IO_删除受保护的PID:
			return IRP_IO_删除受保护的PID(pirp);
		case IO_清空受保护的PID:
			return IRP_IO_清空受保护的PID(pirp);
		case IO_添加需提权的PID:
			return IRP_IO_添加受保护的PID(pirp);
		case IO_删除需提权的PID:
			return IRP_IO_删除需提权的PID(pirp);
		case IO_清空需提权的PID:
			return IRP_IO_清空需提权的PID(pirp);
		case IO_写入受保护的进程:
			return IRP_WriteProcessMemory2(pirp);
		case IO_读取受保护的进程:
			return IRP_ReadProcessMemory2(pirp);;
		case CTL_IO_物理内存读取:
			return IRP_ReadPVirtualMemory(pirp);
		case CTL_IO_物理内存写入:
			return IRP_WritePVirtualMemory(pirp);
		case IO_通过句柄获取对象:
			return IRP_通过句柄获取对象(pirp);
		case IO_通过进程遍历句柄:
			return IRP_通过进程遍历句柄(pirp);
		}
	}
	case IRP_MJ_CREATE:
	{
		//遍历所有驱动保护对象
		EnumObRegisterCallBacks();
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

//NTSTATUS IRP_WRITE(PDEVICE_OBJECT DriverObject, PIRP pirp) {
//	UNREFERENCED_PARAMETER(DriverObject);//一个无效宏
//}
//NTSTATUS IRP_READ(PDEVICE_OBJECT DriverObject, PIRP pirp) {
//	UNREFERENCED_PARAMETER(DriverObject);//一个无效宏
//}

typedef struct _KLDR_DATA__TABLE_ENTRY
{
	LIST_ENTRY listEntry;
	ULONG unknown1;
	ULONG unknown2;
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG Flags;
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("驱动安装\n"));

	PKLDR_DATA_TABLE_ENTRY pobj = DriverObject->DriverSection;
	pobj->Flags |= 0x20;
	//设置卸载例程
	DriverObject->DriverUnload = DriverUnload;

	//设置派遣函数
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_CALL;

	//DriverObject->MajorFunction[IRP_MJ_WRITE] = IRP_WRITE; //对应R3的
	//DriverObject->MajorFunction[IRP_MJ_READ] = IRP_READ;
	//创建驱动对象
	CreateDevice(DriverObject);

	//初始化回调
	ObRegisterCallBacksInit(DriverObject);

	//安装进程保护
	安装进程保护();

	return STATUS_SUCCESS;
}
