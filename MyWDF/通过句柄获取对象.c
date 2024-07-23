#include<ntifs.h>
#include "win10结构体.h"


typedef PHANDLE_TABLE_ENTRY(*PExpLookupHandleTableEntry)(
	IN PHANDLE_TABLE HandleTable,//参数1是句柄表的地址，即 Tablecode，注意，这里 TableCode 的低位不能清要，函数里要判断句柄表结构的
	IN EXHANDLE handle//参数2是句柄值，PID 的值就是一个句柄值，调用 0perproces 打开一个进程得到的也是句柄值，前者用来索引全局句柄表，后者用来索引进程的句柯表。
	);

/*PExpLookupHandleTableEntry ExpLookupHandleTableEntry = (PExpLookupHandleTableEntry)0xfffff80072746b50;
UINT_PTR handleObject=(UINT_PTR) ExpLookupHandleTableEntry((PHANDLE_TABLE)tableCode, *(EXHANDLE*)handle);*/

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
	//获取当前进程指针

	PEPROCESS  currentProcess = PsGetCurrentProcess();
	//指针指向HANDLE_TABLE
	UINT_PTR currentProcessHandleTable = (UINT_PTR)currentProcess + Win10_EPROCESS_HANDLE_TABLE_OFFSET;
	UINT_PTR HANDLE_TABLE = RP(currentProcessHandleTable);

	__try {
		//一定要配置好Win10_ExpLookupHandleTableEntry，否则会蓝屏
		//PExpLookupHandleTableEntry ExpLookupHandleTableEntryZ = (PExpLookupHandleTableEntry)Win10_ExpLookupHandleTableEntry;
		//PHANDLE_TABLE a = (PHANDLE_TABLE)HANDLE_TABLE;
		//EXHANDLE b;
		//b.Value = (ULONG64)handle;
		//UINT_PTR handleObject1 = (UINT_PTR)ExpLookupHandleTableEntryZ(a, b);
		//handleObject1;

		UINT_PTR handleObject2 = MyExpLookupHandleTableEntry(HANDLE_TABLE, (UINT_PTR)handle);
		handleObject2;
		//KdPrint(("驱动 : SYS handleObject1 = %llX handleObject1 = %llX \n", handleObject1, handleObject1));
	}
	__except (1) {
		KdPrint(("驱动:SYS 异常了  +++++++>>>>>>>>>\n\n"));
	}

	if (NT_SUCCESS(status))
	{
		//do something interesting here 如果调用成功 会走到这里
		KeSetEvent(processObject, IO_NO_INCREMENT, FALSE);
		ObDereferenceObject(processObject);
	}
	__debugbreak();
	//KdPrint(("驱动 : SYS handleObject = %llX status = %X handle=%p object=%p \n", handleObject, status, handle, processObject));


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