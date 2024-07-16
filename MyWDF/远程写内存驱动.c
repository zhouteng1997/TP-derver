#include <ntifs.h>
#include "Cr0_HEAD.h"

//��ָ�������ڴ�д������
BOOLEAN KWriteProcessMemory2(
	IN PEPROCESS Process,    //Ŀ�����
	IN PVOID Address,        //Ҫд��ĵ�ַ
	IN UINT32 Length,        //Ҫд������ݳ���
	IN PVOID UserBuffer      //��д�����ݵĻ�����
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

		//����Ȩ���޸ĵ���һ�ַ�������ͬ�� #include "Cr0_HEAD.h"�еķ���
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
		KdPrint(("����: sys64: ������ 37\n"));  //��ӡ������Ϣ
	}

	//��Ŀ����̷���
	KeUnstackDetachProcess(&apc_state);
	KdPrint(("����: sys ����Ŀ�����\n"));  //��ӡ������Ϣ

	if (Mapped) {  //����ڴ�ӳ��ɹ�
		KIRQL kirql = WP_OFF();  //����д����
		RtlCopyMemory(Mapped, UserBuffer, Length);  //�����ݴ� UserBuffer ���Ƶ�Ŀ���ַ
		WP_ON(kirql);  //��������д����
		KdPrint(("���� Mapped = %p UserBuffer = %p Length = %d\n", Mapped, UserBuffer, Length));  //��ӡ������Ϣ
	}
	else {
		KdPrint(("����: sys64: ������ 37\n"));  //��ӡ������Ϣ
	}

	if (Mapped && g_pmdl) {  //����ڴ�ӳ��� MDL ����
		MmUnmapLockedPages((PVOID)Mapped, g_pmdl);  //ȡ�� MDL ���ڴ�ӳ��
	}
	if (g_pmdl) {  //��� MDL ����
		IoFreeMdl(g_pmdl);  //�ͷ� MDL
	}

	return dwRet;  //���ؽ��
}

//���ݽ��� ID ������ڴ�д������
int WriteProcessMemoryForPid2(UINT32 dwPid, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	PEPROCESS Seleted_pEPROCESS = NULL;  //Ŀ�����ָ��
	KdPrint(("����: sys64 %s �к� = %d\n", __FUNCDNAME__, __LINE__));
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(dwPid), &Seleted_pEPROCESS) == STATUS_SUCCESS) {  //���ҽ���
		BOOLEAN br = KWriteProcessMemory2(Seleted_pEPROCESS, pBase, nSize, lpBuffer);  //д������ڴ�
		ObDereferenceObject(Seleted_pEPROCESS);  //ȡ�����ý��̶���
		if (br) {
			return nSize;  //����д��Ĵ�С
		}
	}
	else {
		KdPrint(("���� sys64 PsLookupProcessByProcessId ʧ��\n"));  //��ӡ������Ϣ
	}
	return 0;  //����ʧ��
}

//����д������ڴ�� IRP ����
NTSTATUS IRP_WriteProcessMemory2(PIRP pirp) {
	KdPrint(("����: sys64 %s �к� = %d\n", __FUNCDNAME__, __LINE__));
	NTSTATUS ntStatus = STATUS_SUCCESS;  //��ʼ��״̬Ϊ�ɹ�
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);  //��ȡ��ǰ IRP ��ջλ��

#pragma pack(push)
#pragma pack(8)
	//���뻺�����ṹ��
	typedef struct TINPUT_BUF {
		UINT32 dwPid;   //Ŀ����� ID
		PVOID pBase;    //Ŀ����̵�ַ
		UINT32 nSize;   //Ҫд������ݳ���
		PVOID pbuf;     //Ҫд�����ݵĻ�������ַ
	} TINPUT_BUF;
#pragma pack(pop)

	TINPUT_BUF* bufInput = (TINPUT_BUF*)(pirp->AssociatedIrp.SystemBuffer);  //��ȡ���뻺����
	WriteProcessMemoryForPid2(bufInput->dwPid, bufInput->pBase, bufInput->pbuf, bufInput->nSize);  //д������ڴ�

	KdPrint(("����: sys64 dwPid = %d pBase = %p pbuf = %p nSize = %d\n", bufInput->dwPid, bufInput->pBase, bufInput->pbuf, bufInput->nSize));  //��ӡд����Ϣ

	if (irpStack) {
		if (ntStatus == STATUS_SUCCESS) {  //��������ɹ�
			pirp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;  //���÷��ػ�������С
		}
		else {
			pirp->IoStatus.Information = 0;  //���÷���Ϊ 0
		}
		IoCompleteRequest(pirp, IO_NO_INCREMENT);  //�������
	}

	pirp->IoStatus.Status = ntStatus;  //���� IRP ״̬
	return ntStatus;  //����״̬
}
