#include <ntifs.h>
#include "IO_ReadProcessMemory.h"



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

//创建驱动设备对象
#define 符号链接名 L"\\??\\MyDriver"

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
	UNREFERENCED_PARAMETER(DriverObject);
	//删除驱动对象
	DeleteDriver(DriverObject);
	KdPrint(("驱动卸载\n"));
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
			return IRP_ReadProcessMemory(pirp);
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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("驱动安装\n"));
	//设置卸载例程
	DriverObject->DriverUnload = DriverUnload;
	//设置派遣函数
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_CALL;
	//创建驱动对象
	CreateDevice(DriverObject);
	return STATUS_SUCCESS;
}
