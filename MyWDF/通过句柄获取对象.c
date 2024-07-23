#include<ntifs.h>
#include "win10�ṹ��.h"


typedef PHANDLE_TABLE_ENTRY(*PExpLookupHandleTableEntry)(
	IN PHANDLE_TABLE HandleTable,//����1�Ǿ����ĵ�ַ���� Tablecode��ע�⣬���� TableCode �ĵ�λ������Ҫ��������Ҫ�жϾ����ṹ��
	IN EXHANDLE handle//����2�Ǿ��ֵ��PID ��ֵ����һ�����ֵ������ 0perproces ��һ�����̵õ���Ҳ�Ǿ��ֵ��ǰ����������ȫ�־�������������������̵ľ�±�
	);

/*PExpLookupHandleTableEntry ExpLookupHandleTableEntry = (PExpLookupHandleTableEntry)0xfffff80072746b50;
UINT_PTR handleObject=(UINT_PTR) ExpLookupHandleTableEntry((PHANDLE_TABLE)tableCode, *(EXHANDLE*)handle);*/

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
	//��ȡ��ǰ����ָ��

	PEPROCESS  currentProcess = PsGetCurrentProcess();
	//ָ��ָ��HANDLE_TABLE
	UINT_PTR currentProcessHandleTable = (UINT_PTR)currentProcess + Win10_EPROCESS_HANDLE_TABLE_OFFSET;
	UINT_PTR HANDLE_TABLE = RP(currentProcessHandleTable);

	__try {
		//һ��Ҫ���ú�Win10_ExpLookupHandleTableEntry�����������
		//PExpLookupHandleTableEntry ExpLookupHandleTableEntryZ = (PExpLookupHandleTableEntry)Win10_ExpLookupHandleTableEntry;
		//PHANDLE_TABLE a = (PHANDLE_TABLE)HANDLE_TABLE;
		//EXHANDLE b;
		//b.Value = (ULONG64)handle;
		//UINT_PTR handleObject1 = (UINT_PTR)ExpLookupHandleTableEntryZ(a, b);
		//handleObject1;

		UINT_PTR handleObject2 = MyExpLookupHandleTableEntry(HANDLE_TABLE, (UINT_PTR)handle);
		handleObject2;
		//KdPrint(("���� : SYS handleObject1 = %llX handleObject1 = %llX \n", handleObject1, handleObject1));
	}
	__except (1) {
		KdPrint(("����:SYS �쳣��  +++++++>>>>>>>>>\n\n"));
	}

	if (NT_SUCCESS(status))
	{
		//do something interesting here ������óɹ� ���ߵ�����
		KeSetEvent(processObject, IO_NO_INCREMENT, FALSE);
		ObDereferenceObject(processObject);
	}
	__debugbreak();
	//KdPrint(("���� : SYS handleObject = %llX status = %X handle=%p object=%p \n", handleObject, status, handle, processObject));


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