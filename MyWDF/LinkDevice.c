#include<ntifs.h>
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

