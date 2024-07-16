#include<ntifs.h>

//void 遍历当前句柄所在进程内的所有句柄(IN HANDLE handle) {
//	PEPROCESS process;
//	POBJECT_TYPE objectType;
//	PVOID object;
//}

PVOID 通过句柄获取对象(IN HANDLE handle)
{
	NTSTATUS status;
	PKEVENT processObject = NULL;
	OBJECT_HANDLE_INFORMATION info = { 0 };
	// handle = RetrieveHandleFromIrpBuffer(…)
	__debugbreak();
	KdPrint(("驱动 ObReferenceObjectByHandle info 地址 %p  processObject 地址 %p 句柄为 %p ", &info, &processObject, handle));
	status = ObReferenceObjectByHandle
		(handle,//由我们自己传入进程句柄    rcx
		0x0000,//EVENT ALL ACCESS 0x1FFFFF  rdx
		*PsProcessType,//*ExEventObjectType,//*PsProcessType  r8
		UserMode,   //  r9
		(PVOID*)&processObject,//返回对象 内存地址 rsp+28
		&info); //rsp+30
	KdPrint(("驱动 ObReferenceObjectByHandle info 地址 %p  processObject 地址 %p", &info, &processObject));
	__debugbreak();

	if (NT_SUCCESS(status))
	{
		//do something interesting here 如果调用成功 会走到这里
		KeSetEvent(processObject, IO_NO_INCREMENT, FALSE);
		ObDereferenceObject(processObject);
	}
	KdPrint(("驱动 : SYS status = %X handle=%p object=%p \n", status, handle, processObject));
	return processObject;
}


NTSTATUS IRP_通过句柄获取对象(PIRP pirp) {

	KdPrint(("驱动 : SIRP_通过句柄获取对象 \n"));
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数

	UINT64* 缓冲区 = (UINT64*)pirp->AssociatedIrp.SystemBuffer;
	if (缓冲区)
	{
		HANDLE handle = (HANDLE)(UINT64)缓冲区[0];//传入数据
		PVOID handleObject = 通过句柄获取对象(handle);
		if (handleObject)
			memcpy_s(缓冲区, 8, &handleObject, 8);
	}
	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 8;//返回给DeviceIoContral中的倒数第二个参数IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//调用方已完成所有的io请求处理操作，并不增加优先级
	return STATUS_SUCCESS;
}