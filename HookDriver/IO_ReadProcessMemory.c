#include "IO_ReadProcessMemory.h"
#include "win10api.h"

//��ȡ�����ڴ�ĺ���
BOOLEAN KReadProcessMemory2(
	IN PEPROCESS Process,    //Ŀ�����
	IN PVOID Address,        //Ҫ��ȡ�ĵ�ַ
	IN UINT32 Length,        //Ҫ��ȡ�����ݳ���
	IN PVOID UserBuffer      //��Ŷ�ȡ���ݵĻ�����
) {
	unsigned char* Mapped = NULL;      //ӳ���ڴ�ָ��
	PMDL g_pmdl = NULL;                //�ڴ��������б�ָ��
	KAPC_STATE apc_state;              //APC ״̬���ڽ��̸���
	RtlZeroMemory(&apc_state, sizeof(KAPC_STATE));  //���� APC ״̬�ṹ��
	KdPrint(("����: sys64 %s �к� = %d (Process = %p, Address = %p, Length = %d, UserBuffer = %p)\n", __FUNCDNAME__, __LINE__, Process, Address, Length, UserBuffer));

	//���ӵ�Ŀ����̵ĵ�ַ�ռ�
	KeStackAttachProcess((PVOID)Process, &apc_state);
	BOOLEAN dwRet = MmIsAddressValid(Address);  //����ַ�Ƿ���Ч

	if (dwRet) {
		//�����ڴ��������б� (MDL)
		g_pmdl = IoAllocateMdl(Address, Length, 0, 0, NULL);

		if (!g_pmdl) {  //�������ʧ��
			KeUnstackDetachProcess(&apc_state);  //��Ŀ����̷���
			return FALSE;  //����ʧ��
		}

		//�������ڷǷ�ҳ�ص� MDL
		MmBuildMdlForNonPagedPool(g_pmdl);

		//����Ȩ���޸�
		//g_pmdl->MdlFlags = MDL_WRITE_OPERATION | MDL_ALLOCATED_FIXED_SIZE | MDL_PAGES_LOCKED;

		//�� MDL ӳ�䵽�ں˿ռ�
		unsigned char* Mapped1 = (unsigned char*)MmMapLockedPages(g_pmdl, KernelMode);
		Mapped = Mapped1;  //����ӳ���ڴ�ָ��
		if (!Mapped) {  //���ӳ��ʧ��
			IoFreeMdl(g_pmdl);  //�ͷ� MDL
			KeUnstackDetachProcess(&apc_state);  //��Ŀ����̷���
			return FALSE;  //����ʧ��
		}
	}
	else {
		KdPrint(("����: sys64: ������ %d\n",__LINE__));  //��ӡ������Ϣ
	}

	//��Ŀ����̷���
	KeUnstackDetachProcess(&apc_state);
	KdPrint(("����: sys ����Ŀ�����\n"));  //��ӡ������Ϣ

	if (Mapped) {  //����ڴ�ӳ��ɹ�
		RtlCopyMemory(UserBuffer, Mapped, Length);  //�����ڴ����ݵ��û�������
		KdPrint(("���� Mapped = %p UserBuffer = %p Length = %d\n", Mapped, UserBuffer, Length));  //��ӡ������Ϣ
	}
	else {
		KdPrint(("����: sys64: ������ %d\n", __LINE__));  //��ӡ������Ϣ
	}

	if (Mapped && g_pmdl) {  //����ڴ�ӳ��� MDL ����
		MmUnmapLockedPages((PVOID)Mapped, g_pmdl);  //ȡ�� MDL ���ڴ�ӳ��
	}
	if (g_pmdl) {  //��� MDL ����
		IoFreeMdl(g_pmdl);  //�ͷ� MDL
	}

	return dwRet;  //���ؽ��
}

//���ݽ��� ID ��ȡ�����ڴ�
int ReadProcessMemoryForPid2(HANDLE dwPid, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	PEPROCESS Seleted_pEPROCESS = NULL;  //Ŀ�����ָ��
	DbgPrint("����: sys64 %s �к� = %d\n", __FUNCDNAME__, __LINE__);
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(dwPid), &Seleted_pEPROCESS) == STATUS_SUCCESS) {  //���ҽ���
		BOOLEAN br = KReadProcessMemory2(Seleted_pEPROCESS, pBase, nSize, lpBuffer);  //��ȡ�����ڴ�
		ObDereferenceObject(Seleted_pEPROCESS);  //ȡ�����ý��̶���
		if (br) {
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
