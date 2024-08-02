#include "IO_ZwQueryVirtualMemory.h"
#include "win10api.h"

//��ȡ�����ڴ�ĺ���
NTSTATUS ZwQueryVirtualMemory2(
	IN PEPROCESS Process,    //Ŀ�����
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
) {

	__debugbreak();

	//ӳ��mdl
	PMDL pmdl_MemoryInformation = IoAllocateMdl(MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION), 0, 0, NULL);
	PMDL pmdl_ReturnLength = IoAllocateMdl(ReturnLength, 8, 0, 0, NULL);

	unsigned char* Mapped_MemoryInformation = {0};
	PSIZE_T Mapped_ReturnLength=0;

	//ӳ���ں�
	if (MemoryInformation)
	{
		MmBuildMdlForNonPagedPool(pmdl_MemoryInformation);
		unsigned char* Mapped_MemoryInformation1 = (unsigned char*)MmMapLockedPages(pmdl_MemoryInformation, KernelMode);
		Mapped_MemoryInformation = Mapped_MemoryInformation1;
	}
	//ӳ���ں�
	if (pmdl_ReturnLength)
	{
		MmBuildMdlForNonPagedPool(pmdl_ReturnLength);
		PSIZE_T Mapped_ReturnLength1 = (PSIZE_T)MmMapLockedPages(pmdl_ReturnLength, KernelMode);
		Mapped_ReturnLength = Mapped_ReturnLength1;
	}

	//���ӽ���
	KAPC_STATE apc_state;
	KeStackAttachProcess((PVOID)Process, &apc_state);
	//����ZwQueryVirtualMemory
	if(Mapped_MemoryInformation && Mapped_ReturnLength)
	ZwQueryVirtualMemory(NtCurrentProcess(), BaseAddress, MemoryInformationClass,
		(PVOID)Mapped_MemoryInformation, MemoryInformationLength, (PSIZE_T)Mapped_ReturnLength);
	//��Ŀ����̷���
	KeUnstackDetachProcess(&apc_state);


	//ȡ�� MDL ���ڴ�ӳ��
	if (Mapped_MemoryInformation && pmdl_MemoryInformation)
		MmUnmapLockedPages((PVOID)Mapped_MemoryInformation, pmdl_MemoryInformation);
	//�ͷ� MDL
	if (pmdl_MemoryInformation)
		IoFreeMdl(pmdl_MemoryInformation);
	//ȡ�� MDL ���ڴ�ӳ��
	if (Mapped_ReturnLength && pmdl_ReturnLength)
		MmUnmapLockedPages((PVOID)Mapped_ReturnLength, pmdl_ReturnLength);
	//�ͷ� MDL
	if (pmdl_ReturnLength)
		IoFreeMdl(pmdl_ReturnLength);

	return STATUS_SUCCESS;
}

NTSTATUS ZwQueryVirtualMemoryForHandle(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
) {
	//��ȡpid
	HANDLE pid = HandleToPid(PsGetCurrentProcessId(), ProcessHandle);
	//����pep
	PEPROCESS Seleted_pEPROCESS = NULL;  //Ŀ�����ָ�� pep
	//�õ�pep
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)(pid), &Seleted_pEPROCESS)))
		KdPrint(("���� sys64 PsLookupProcessByProcessId ʧ��\n"));  //��ӡ������Ϣ
	//�����Լ�д��ZwQueryVirtualMemory
	NTSTATUS result = ZwQueryVirtualMemory2(Seleted_pEPROCESS, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);  //��ȡ�����ڴ�
	//ȡ�����ý��̶���
	ObDereferenceObject(Seleted_pEPROCESS);
	//����
	return result;
}

//���� IRP ��ȡ�����ڴ�
NTSTATUS IRP_ZwQueryVirtualMemory(PIRP pirp) {
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	irpStack;
	UINT64* ������ = (UINT64*)(pirp->AssociatedIrp.SystemBuffer);
	if (������)
	{
#pragma pack(push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			HANDLE                   ProcessHandle;//���
			PVOID                    BaseAddress;///Ŀ����̵�ַ
			MEMORY_INFORMATION_CLASS MemoryInformationClass;
			PVOID                    MemoryInformation;
			SIZE_T                   MemoryInformationLength;
			PSIZE_T                  ReturnLength;
		}TINPUT_BUF;
#pragma pack (pop)
		TINPUT_BUF* bufInput = (TINPUT_BUF*)������;  //��ȡ���뻺����

		NTSTATUS result = ZwQueryVirtualMemoryForHandle(bufInput->ProcessHandle, bufInput->BaseAddress, bufInput->MemoryInformationClass,
			bufInput->MemoryInformation, bufInput->MemoryInformationLength, bufInput->ReturnLength);  //��ȡ�����ڴ�


		UINT64* ��������� = ������;
		���������[0] = result;

		if (NT_SUCCESS(result))
		{
			pirp->IoStatus.Status = STATUS_SUCCESS;
			pirp->IoStatus.Information = sizeof(UINT64);  //���÷��ػ�������С
			IoCompleteRequest(pirp, IO_NO_INCREMENT);  //�������
			return STATUS_SUCCESS;
		}
		else {
			return -1;
		}
	}
	return -1;  //����״̬
}
