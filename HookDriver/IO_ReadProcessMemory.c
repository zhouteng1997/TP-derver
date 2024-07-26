#include "IO_ReadProcessMemory.h"
#include "win10api.h"


BOOLEAN IsOkWritePrt(UINT_PTR base) {
	__try {
		*(UINT64*)base;
		return TRUE;
	}
	__except (1) {
		return FALSE;
	}
}

//��ȡ�����ڴ�ĺ���
NTSTATUS KReadProcessMemory2(
	IN PEPROCESS Process,    //Ŀ�����
	IN PVOID Address,        //Ҫ��ȡ�ĵ�ַ
	IN UINT32 Length,        //Ҫ��ȡ�����ݳ���
	IN PVOID UserBuffer      //��Ŷ�ȡ���ݵĻ�����
) {
	KAPC_STATE apc_state;              //APC ״̬���ڽ��̸���
	PVOID tmpBuf_Kernel = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	// ���ӵ�Ŀ����̵ĵ�ַ�ռ�
	KeStackAttachProcess((PVOID)Process, &apc_state);
	// ����ַ�Ƿ���Ч
	if (MmIsAddressValid(Address)) {
		// ����ַ�Ƿ����д��
		if (IsOkWritePrt((UINT_PTR)Address)) {
			__try {
				// �����ڴ沢����Ƿ�ɹ�
				PVOID tmpBuf_Kerne2 = ExAllocatePool(NonPagedPool, Length);
				tmpBuf_Kernel = tmpBuf_Kerne2;
				if (tmpBuf_Kernel == NULL) {
					status = STATUS_INSUFFICIENT_RESOURCES;
				}
				else {
					// ��ȡ�ڴ�
					RtlCopyMemory(tmpBuf_Kernel, Address, Length);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				KdPrint(("����: sys64: ������ %d\n", __LINE__));
				status = STATUS_ACCESS_VIOLATION;
			}
		}
		else {
			status = STATUS_ACCESS_DENIED;
		}
	}
	else {
		KdPrint(("����: sys64: ������ %d\n", __LINE__));
		status = STATUS_INVALID_ADDRESS;
	}
	// ��Ŀ����̷���
	KeUnstackDetachProcess(&apc_state);
	if (NT_SUCCESS(status) && tmpBuf_Kernel != NULL) {
		// ������ָ���û�������
		__try {
			RtlCopyMemory(UserBuffer, tmpBuf_Kernel, Length);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			KdPrint(("����: sys64: ������ %d\n", __LINE__));
			status = STATUS_ACCESS_VIOLATION;
		}
		// �ͷŷ�����ڴ�
		ExFreePool(tmpBuf_Kernel);
	}
	return status;  // ���ؽ��
}

//���ݽ��� ID ��ȡ�����ڴ�
int ReadProcessMemoryForPid2(HANDLE dwPid, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	PEPROCESS Seleted_pEPROCESS = NULL;  //Ŀ�����ָ��
	DbgPrint("����: sys64 %s �к� = %d\n", __FUNCDNAME__, __LINE__);
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(dwPid), &Seleted_pEPROCESS) == STATUS_SUCCESS) {  //���ҽ���
		NTSTATUS br = KReadProcessMemory2(Seleted_pEPROCESS, pBase, nSize, lpBuffer);  //��ȡ�����ڴ�
		ObDereferenceObject(Seleted_pEPROCESS);  //ȡ�����ý��̶���
		if (NT_SUCCESS(br)) {
			return nSize;  //���ض�ȡ�Ĵ�С
		}
	}
	else {
		KdPrint(("���� sys64 PsLookupProcessByProcessId ʧ��\n"));  //��ӡ������Ϣ
	}
	return 0;  //����ʧ��
}


int ReadProcessMemoryForHandle(HANDLE handle, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	HANDLE pid = HandleToPid(PsGetCurrentProcessId(), handle);
	return ReadProcessMemoryForPid2(pid, pBase, lpBuffer, nSize);
}

//���� IRP ��ȡ�����ڴ�
NTSTATUS IRP_ReadProcessMemory(PIRP pirp) {
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	irpStack;
	UINT64* ������ = (UINT64*)(pirp->AssociatedIrp.SystemBuffer);
	if (������)
	{
#pragma pack(push)
#pragma pack(8)
		//���뻺�����ṹ��
		typedef struct TINPUT_BUF {
			HANDLE handle;   //Ŀ����� ID
			PVOID pBase;    //Ŀ����̵�ַ
			UINT32 nSize;   //Ҫ��ȡ�����ݳ���
		} TINPUT_BUF;
#pragma pack(pop)
		TINPUT_BUF* bufInput = (TINPUT_BUF*)������;  //��ȡ���뻺����
		UINT32 ReadSize = ReadProcessMemoryForHandle(bufInput->handle, bufInput->pBase, ������, bufInput->nSize);  //��ȡ�����ڴ�
		ReadSize;
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = bufInput->nSize;  //���÷��ػ�������С
		IoCompleteRequest(pirp, IO_NO_INCREMENT);  //�������
		if (ReadSize)
		{
			return STATUS_SUCCESS;
		}
		else {
			return -1;
		}
	}
	return -1;  //����״̬
}
