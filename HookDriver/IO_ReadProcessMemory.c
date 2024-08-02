#include "IO_ReadProcessMemory.h"
#include "win10api.h"


UINT_PTR PR(UINT_PTR base) {
	__try {
		return *(UINT_PTR*)base;
	}
	__except (1) {
		return 0;
	}
}

BOOLEAN IsOkReadPtr(UINT_PTR base) {
	__try {
		*(UINT64*)base;
		return TRUE;
	}
	__except (1) {
		return FALSE;
	}
}

size_t i64abs(INT64 value) {
	INT64 retvalue = value;
	if (value < 0) {
		retvalue = ~value + 1;
	}
	return (size_t)retvalue;
}

size_t mymemcpy_s(char* dest, const char* src, size_t len) {
	__try {
		size_t num = 0;
		if (!src || !dest) return 0;
		size_t diff = i64abs((INT64)dest - (INT64)src);

		if (diff<len && dest>src)//�ص�����Ŀ���ַ����Դ��ַ ����Ҫ��������
		{
			int len08 = (int)(len / 8);
			int len01 = len % 8;
			{
				UINT64* p1 = (UINT64*)dest;
				UINT64* p2 = (UINT64*)src;
				for (int i = len08 - 1; i >= 0; i--) {
					p1[i] = p2[i];
					num += 8;
				}
			}
			{
				char* p1 = (char*)dest + len08 * 8;
				char* p2 = (char*)src + len08 * 8;
				for (int i = len01 - 1; i > 0; i--) {
					p1[i] = p2[i];
					num += 1;
				}
			}
		}
		else
		{
			int len08 = (int)(len / 8);
			int len01 = len % 8;
			{
				UINT64* p1 = (UINT64*)dest;
				UINT64* p2 = (UINT64*)src;
				for (int i = 0; i < len08; i++) {
					p1[i] = p2[i];
					num += 8;
				}
			}
			{
				char* p1 = (char*)dest + len08 * 8;
				char* p2 = (char*)src + len08 * 8;
				for (int i = 0; i < len01; i++) {
					p1[i] = p2[i];
					num += 1;
				}
			}
		}
		return num;
	}
	__except (1) {}
	return 0;
}

// x HookDriver!ReadProcessMemory2
//��ȡ�����ڴ�ĺ���
NTSTATUS ReadProcessMemory2(
	IN PEPROCESS pep,    //Ŀ�����
	IN PVOID lpBaseAddress,        //Ҫ��ȡ�ĵ�ַ
	IN PVOID lpBuffer,      //��Ŷ�ȡ���ݵĻ�����
	IN UINT32 nSize,        //Ҫ��ȡ�����ݳ���
	IN UINT_PTR lpNumberOfBytesRead        //��ȡ�����ݳ���
) {
	pep;
	lpBaseAddress;
	lpBuffer;
	nSize;
	lpNumberOfBytesRead;

	KdPrint(("���� ReadProcessMemory2 lpBaseAddress=%p,lpBuffer=%p,nSize=%x,lpNumberOfBytesRead=%x \n",
		lpBaseAddress, lpBuffer, nSize, (UINT32)lpNumberOfBytesRead));  //��ӡ������Ϣ

	if (!IsOkReadPtr(PR((UINT_PTR)lpBuffer)))//�������ڴ治�������
		return STATUS_UNSUCCESSFUL;

	UINT64 num = 0;
	NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
	KAPC_STATE apc_state;
	RtlZeroMemory(&apc_state, sizeof(KAPC_STATE));//����ռ�

	PMDL mdl = IoAllocateMdl(lpBuffer, nSize, FALSE, FALSE, NULL);//ӳ��mdl
	if (!mdl)
	{
		return STATUS_UNSUCCESSFUL;
	}
	MmBuildMdlForNonPagedPool(mdl);//���δ��ҳ
	unsigned char* lpBuffer_Mapper = (unsigned char*)MmMapLockedPages(mdl, KernelMode);//ӳ�䵽�ں�

	if (!lpBuffer_Mapper)
	{
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	KeStackAttachProcess(pep, &apc_state);//�л���Ŀ�����


	if (IsOkReadPtr((UINT_PTR)lpBaseAddress))
	{
		__try {
			num = mymemcpy_s((char*)lpBuffer_Mapper, (const char*)lpBaseAddress, (size_t)nSize);
			retStatus = STATUS_SUCCESS;
		}
		__except (1) {}
	}


	KeUnstackDetachProcess(&apc_state);//����Ŀ�����
	MmUnmapLockedPages((PVOID)lpBuffer_Mapper, mdl);
	IoFreeMdl(mdl);
	if (num)
	{
		__try {
			*(UINT32*)lpNumberOfBytesRead = (UINT32)num;
		}
		__except (1) {}
	}
	return retStatus;
}


NTSTATUS ReadProcessMemoryForHandle(HANDLE handle, PVOID lpBaseAddress, PVOID lpBuffer, UINT32 nSize, UINT_PTR lpNumberOfBytesRead) {
	HANDLE pid = HandleToPid(PsGetCurrentProcessId(), handle);
	if (pid) {
		NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
		PEPROCESS pep = NULL;  //Ŀ�����ָ��
		if (PsLookupProcessByProcessId(pid, &pep) == STATUS_SUCCESS) {  //���ҽ���
			retStatus = ReadProcessMemory2(pep, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);  //��ȡ�����ڴ�
			ObDereferenceObject(pep);  //ȡ�����ý��̶���
		}
		return retStatus;
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}
}

//���� IRP ��ȡ�����ڴ�
NTSTATUS IRP_ReadProcessMemory(PIRP pirp) {
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	irpStack;
	UINT64* ������ = (UINT64*)(pirp->AssociatedIrp.SystemBuffer);
	if (������)
	{
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			UINT64 hProcess;//���
			UINT64 lpBaseAddress;///Ŀ����̵�ַ
			UINT64 lpBuffer;//���մ�Ŀ����̶�ȡ�����ݵĻ�����
			UINT64 nSize;//Ҫ��ȡ���ֽ���
			UINT64 lpNumberOfBytesRead; //ʵ�ʶ�ȡ���ֽ���
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF* input = (TINPUT_BUF*)������;  //��ȡ���뻺����
		INT64* ret = (INT64*)������;
		NTSTATUS retStatus = ReadProcessMemoryForHandle((HANDLE)input->hProcess, (PVOID)input->lpBaseAddress,
			(PVOID)input->lpBuffer, (UINT32)input->nSize, (UINT_PTR)input->lpNumberOfBytesRead);  //��ȡ�����ڴ�


		if (NT_SUCCESS(retStatus))
		{
			*ret = 1;
			pirp->IoStatus.Status = STATUS_SUCCESS;
			pirp->IoStatus.Information = sizeof(INT64);  //���÷��ػ�������С
		}
		else {
			*ret = 0;
			pirp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			pirp->IoStatus.Information = sizeof(INT64);  //���÷��ػ�������С
		}
		IoCompleteRequest(pirp, IO_NO_INCREMENT);  //�������
	}
	return STATUS_SUCCESS;  //����״̬
}
