#include<ntifs.h>

//void ������ǰ������ڽ����ڵ����о��(IN HANDLE handle) {
//	PEPROCESS process;
//	POBJECT_TYPE objectType;
//	PVOID object;
//}

PVOID ͨ�������ȡ����(IN HANDLE handle)
{
	NTSTATUS status;
	PKEVENT processObject = NULL;
	OBJECT_HANDLE_INFORMATION info = { 0 };
	// handle = RetrieveHandleFromIrpBuffer(��)
	__debugbreak();
	KdPrint(("���� ObReferenceObjectByHandle info ��ַ %p  processObject ��ַ %p ���Ϊ %p ", &info, &processObject, handle));
	status = ObReferenceObjectByHandle
		(handle,//�������Լ�������̾��    rcx
		0x0000,//EVENT ALL ACCESS 0x1FFFFF  rdx
		*PsProcessType,//*ExEventObjectType,//*PsProcessType  r8
		UserMode,   //  r9
		(PVOID*)&processObject,//���ض��� �ڴ��ַ rsp+28
		&info); //rsp+30
	KdPrint(("���� ObReferenceObjectByHandle info ��ַ %p  processObject ��ַ %p", &info, &processObject));
	__debugbreak();

	if (NT_SUCCESS(status))
	{
		//do something interesting here ������óɹ� ���ߵ�����
		KeSetEvent(processObject, IO_NO_INCREMENT, FALSE);
		ObDereferenceObject(processObject);
	}
	KdPrint(("���� : SYS status = %X handle=%p object=%p \n", status, handle, processObject));
	return processObject;
}


NTSTATUS IRP_ͨ�������ȡ����(PIRP pirp) {

	KdPrint(("���� : SIRP_ͨ�������ȡ���� \n"));
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���

	UINT64* ������ = (UINT64*)pirp->AssociatedIrp.SystemBuffer;
	if (������)
	{
		HANDLE handle = (HANDLE)(UINT64)������[0];//��������
		PVOID handleObject = ͨ�������ȡ����(handle);
		if (handleObject)
			memcpy_s(������, 8, &handleObject, 8);
	}
	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 8;//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	return STATUS_SUCCESS;
}