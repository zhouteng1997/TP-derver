#include "ntifs.h"

//�����ַ�����ֵ
UINT64 g_maxPhysAddress = 0;

//��ȡ�����ַ�����ֵ
UINT64 getg_maxPhysAddress(void)
{
	if (g_maxPhysAddress == 0)
	{
		int physicalbits;
		UINT32 r[4]; //�洢CPUIDָ��ص���Ϣ
		__cpuid(r, 0x80000008); //��ȡ�����ַλ��
		physicalbits = r[0] & 0xff; //ȡ��ǰ8λ�������ַλ��
		g_maxPhysAddress = 0xFFFFFFFFFFFFFFFFULL;
		g_maxPhysAddress = g_maxPhysAddress >> physicalbits; //������������ַ
		g_maxPhysAddress = ~(g_maxPhysAddress << physicalbits); //����ʵ�ʵ������ַ����
	}
	return g_maxPhysAddress; //������������ַ
}

//��ȡ�����ڴ�
BOOLEAN ReadPhysicalMemory(char* physicalBase, UINT_PTR bytestoread, void* output)
{
	HANDLE physmem;
	UNICODE_STRING physmemString;
	OBJECT_ATTRIBUTES attributes;
	const WCHAR* physmemName = L"\\device\\physicalmemory"; //�����ڴ��豸��
	UCHAR* vaddress; //ӳ�������ַ
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PMDL outputMDL; //��Ŷ�ȡ�����ݵ�MDL

	KdPrint(("���� ��ReadPhysicalMemory(%p, %lld, %p)", physicalBase, bytestoread, output));

	if (((UINT64)physicalBase > getg_maxPhysAddress()) || ((UINT64)physicalBase + bytestoread > getg_maxPhysAddress()))
	{
		KdPrint(("���� ��SYS Invalid physical address\n"));
		return ntStatus == FALSE; //�����ַ��Ч�򷵻�ʧ��
	}

	outputMDL = IoAllocateMdl(output, (ULONG)bytestoread, FALSE, FALSE, NULL);

	__try
	{
		MmProbeAndLockPages(outputMDL, KernelMode, IoWriteAccess); //�����ڴ�ҳ����ֹ����ҳ��ȥ
	}
	__except (1)
	{
		IoFreeMdl(outputMDL); //�����ڴ�ҳ
		return FALSE;
	}

	__try
	{
		RtlInitUnicodeString(&physmemString, physmemName); //��ʼ�������ڴ��豸�ַ���
		InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL); //��ʼ����������
		ntStatus = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes); //�������ڴ��豸

		if (ntStatus == STATUS_SUCCESS)
		{
			SIZE_T length;
			PHYSICAL_ADDRESS viewBase; //�����ڴ��ַ
			UINT_PTR offset;
			UINT_PTR toread;

			viewBase.QuadPart = (ULONGLONG)(physicalBase);
			length = 0x2000; //��ȡ����
			toread = bytestoread;
			vaddress = NULL;

			KdPrint(("���� ��ReadPhysicalMemory:viewBase.QuadPart=%x", viewBase.QuadPart));

			//ӳ�������ڴ��ַ����ǰ���̵����ַ�ռ�
			ntStatus = ZwMapViewOfSection(
				physmem, //�����ڴ���
				NtCurrentProcess(), //��ǰ���̾��
				&vaddress, //ӳ�������ַ
				0L, //��λ
				length, //�ύ��С
				&viewBase, //��ƫ��
				&length, //��ͼ��С
				ViewShare,
				0,
				PAGE_READWRITE //��дȨ��
			);

			if ((ntStatus == STATUS_SUCCESS) && (vaddress != NULL))
			{
				if (toread > length)
					toread = length;

				if (toread)
				{
					__try
					{
						offset = (UINT_PTR)(physicalBase)-(UINT_PTR)viewBase.QuadPart; //����ƫ����

						if (offset + toread > length)
						{
							KdPrint(("���� ��Too small map"));
							__noop(("���� ��Too small map"));
						}
						else
						{
							RtlCopyMemory(output, &vaddress[offset], toread); //�����ڴ�����
						}
						ZwUnmapViewOfSection(NtCurrentProcess(), vaddress); //ȡ��ӳ��
					}
					__except (1)
					{
						KdPrint(("���� ��Failure mapping physical memory"));
					}
				}
			}
			else
			{
				KdPrint(("���� ��ReadPhysicalMemory error:ntStatus=%x", ntStatus));
			}
			ZwClose(physmem); //�ر������ڴ���
		}
	}
	__except (1)
	{
		KdPrint(("���� ��Error while reading physical memory\n"));
	}

	MmUnlockPages(outputMDL); //�����ڴ�ҳ
	IoFreeMdl(outputMDL); //�ͷ�MDL

	return ntStatus == STATUS_SUCCESS ? TRUE : FALSE; //���ض�ȡ���
}

//д�������ڴ�
BOOLEAN WritePhysicalMemory(char* physicalBase, IN UINT_PTR nSizeWrite, IN PVOID InBuf)
{
	HANDLE physmem;
	UNICODE_STRING physmemString;
	OBJECT_ATTRIBUTES attributes;
	const WCHAR* physmemName = L"\\device\\physicalmemory"; //�����ڴ��豸��
	UCHAR* vaddress = NULL; //ӳ�������ַ
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PMDL pInBufMDL = NULL; //���д�����ݵ�MDL

	KdPrint(("���� ��SYS:WritePhysicalMemory(%p, %lld, %p)", physicalBase, nSizeWrite, InBuf));

	if (((UINT64)physicalBase > getg_maxPhysAddress()) || ((UINT64)physicalBase + nSizeWrite > getg_maxPhysAddress()))
	{
		KdPrint(("���� ��SYS:Error Invalid physical address\n"));
		return ntStatus == FALSE; //�����ַ��Ч�򷵻�ʧ��
	}

	//IoAllocateMdl ���̷����ڴ��������б� (MDL) ����ӳ�仺����
	pInBufMDL = IoAllocateMdl(InBuf, (ULONG)nSizeWrite, FALSE, FALSE, NULL);

	__try
	{
		MmProbeAndLockPages(pInBufMDL, KernelMode, IoWriteAccess); //�����ڴ�ҳ����ֹ����ҳ��ȥ
	}
	__except (1)
	{
		IoFreeMdl(pInBufMDL); //�ͷ�MDL
		KdPrint(("���� ��SYS:Error InBuf MmProbeAndLockPages fail \n"));
		return FALSE;
	}

	PVOID pMapedAddr = NULL;

	__try
	{
		//ӳ��������ҳ�������ַ�ռ�
		pMapedAddr = MmMapLockedPagesSpecifyCache(pInBufMDL, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

		if (!pMapedAddr)
		{
			KdPrint(("���� ��SYS:pMapedAdd == NULL\n"));
			return 0;
		}
	}
	__except (1)
	{
		KdPrint(("���� ��SYS:MmMapLockedPagesSpecifyCache ӳ���ڴ�ʧ�� pMapedAddr=%p\n", pMapedAddr));
		return 0;
	}

	__try
	{
		RtlInitUnicodeString(&physmemString, physmemName); //��ʼ�������ڴ��豸�ַ���
		InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL); //��ʼ����������
		ntStatus = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes); //�������ڴ��豸

		if (ntStatus == STATUS_SUCCESS)
		{
			SIZE_T length;
			PHYSICAL_ADDRESS viewBase; //�����ڴ��ַ
			UINT_PTR offset;
			UINT_PTR toWriteSize;

			viewBase.QuadPart = (ULONGLONG)(physicalBase);
			length = 0x2000; //д�볤��
			toWriteSize = nSizeWrite;
			vaddress = NULL;

			KdPrint(("���� ��SYS:ReadPhysicalMemory:��ַ=%lld", viewBase.QuadPart));

			//ӳ�������ڴ��ַ����ǰ���̵����ַ�ռ�
			ntStatus = ZwMapViewOfSection(
				physmem, //�����ڴ���
				NtCurrentProcess(), //��ǰ���̾��
				&vaddress, //ӳ�������ַ
				0L, //��λ
				length, //�ύ��С
				&viewBase, //��ƫ��
				&length, //��ͼ��С
				ViewShare,
				0,
				PAGE_READWRITE //��дȨ��
			);

			if ((ntStatus == STATUS_SUCCESS) && (vaddress != NULL))
			{
				if (toWriteSize > length)
					toWriteSize = length;

				if (toWriteSize)
				{
					__try
					{
						offset = (UINT_PTR)(physicalBase)-(UINT_PTR)viewBase.QuadPart; //����ƫ����

						if (offset + toWriteSize > length)
						{
							KdPrint(("���� ���ڴ�ӳ��̫С"));
							__noop(("���� ���ڴ�ӳ��̫С"));
						}
						else
						{
							RtlCopyMemory(&vaddress[offset], pMapedAddr, toWriteSize); //�������ݵ��ڴ�
						}
						ZwUnmapViewOfSection(NtCurrentProcess(), vaddress); //ȡ��ӳ��
					}
					__except (1)
					{
						KdPrint(("���� ��ӳ�������ڴ�ʧ��"));
					}
				}
			}
			else
			{
				KdPrint(("���� ��ReadPhysicalMemory error:ntStatus=%x", ntStatus));
			}
			ZwClose(physmem); //�ر������ڴ���
		}
	}
	__except (1)
	{
		KdPrint(("���� ���������ڴ����\n"));
	}

	MmUnmapLockedPages(pMapedAddr, pInBufMDL); //ȡ��ӳ������ҳ
	MmUnlockPages(pInBufMDL); //�����ڴ�ҳ
	IoFreeMdl(pInBufMDL); //�ͷ�MDL

	return ntStatus == STATUS_SUCCESS ? TRUE : FALSE; //����д����
}

//��ȡ�����ַ
PVOID GetPhysicalAddress(UINT32 ProcessID, PVOID vBaseAddress)
{

	KdPrint(("��������ʼ��ȡ�����ַ ProcessID=%d  vBaseAddress=%p", ProcessID, vBaseAddress));
	PEPROCESS selectedprocess; //���ָ��ProcessID��PEPROCESS
	PHYSICAL_ADDRESS physical; //���ص������ַ
	physical.QuadPart = 0; //��ʼ�������ַ
	NTSTATUS ntStatus = STATUS_SUCCESS; //��ʼ��״̬Ϊ�ɹ�

	__try
	{
		//����ָ���Ľ���
		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(ProcessID), &selectedprocess) == STATUS_SUCCESS)
		{
			KAPC_STATE apc_state; //����APC״̬
			RtlZeroMemory(&apc_state, sizeof(apc_state)); //����APC״̬

			//���ӵ�ָ�����̵�������
			KeStackAttachProcess((PVOID)selectedprocess, &apc_state);

			__try
			{
				//�������ַת��Ϊ�����ַ
				physical = MmGetPhysicalAddress((PVOID)vBaseAddress);
			}
			__finally
			{
				//��ָ�����̵������ķ���
				KeUnstackDetachProcess(&apc_state);
			}
			//ȡ���Խ��̶��������
			ObDereferenceObject(selectedprocess);
		}
	}
	__except (1)
	{
		ntStatus = STATUS_UNSUCCESSFUL; //�����쳣������״̬Ϊʧ��
	}

	//���״̬�ɹ����򷵻������ַ
	if (ntStatus == STATUS_SUCCESS)
	{
		return (PVOID)physical.QuadPart;
	}

	return NULL; //���򷵻�NULL
}

//�������ڴ�
BOOLEAN ReadPVirtualMemory(UINT32 ProcessID, IN PVOID VBaseAddress, IN UINT32 nSize, OUT PVOID pBuf)
{
	KdPrint(("������SYS:WritePVirtualMemory ProcessID= %d,VBaseAddress=%p,nSize=%d,pBuf=%p", ProcessID, VBaseAddress, nSize, pBuf));
	PVOID phyBase = GetPhysicalAddress(ProcessID, VBaseAddress); //��ȡ�����ַ

	if (phyBase)
	{
		//��ȡ�����ڴ�
		return ReadPhysicalMemory(phyBase, nSize, pBuf);
	}
	else
	{
		return FALSE; //��ȡ�����ַʧ�ܷ���FALSE
	}
}

//д�����ڴ�
BOOLEAN WritePVirtualMemory(UINT32 ProcessID, IN PVOID VBaseAddress, IN UINT32 nSize, IN PVOID pBuf)
{
	KdPrint(("������SYS:WritePVirtualMemory ProcessID= %d,VBaseAddress=%p,nSize=%d,pBuf=%p", ProcessID, VBaseAddress, nSize, pBuf));
	PVOID phyBase = GetPhysicalAddress(ProcessID, VBaseAddress); //��ȡ�����ַ

	if (phyBase)
	{
		//д�������ڴ�
		return WritePhysicalMemory(phyBase, nSize, pBuf);
	}
	else
	{
		return FALSE; //��ȡ�����ַʧ�ܷ���FALSE
	}
}

//���ڴ�
NTSTATUS IRP_ReadPVirtualMemory(PIRP pirp)
{
	KdPrint(("������sys64 %s �к�=%d", __FUNCDNAME__, __LINE__));
	NTSTATUS ntStatus = STATUS_SUCCESS; //��ʼ��״̬Ϊ�ɹ�
	PIO_STACK_LOCATION irpStack = NULL; //��ʼ��IO��ջλ��
	irpStack = IoGetCurrentIrpStackLocation(pirp); //��ȡ��ǰ��IRP��ջλ��

#pragma pack(push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 ProcessID; //Ŀ�����PID
		PVOID VBaseAddress; //Ŀ����������ַ
		UINT32 nSize; //��ȡ�ĳ���
		PVOID pBuf; //���Դ��ֶ�
	} TINPUT_BUF;
#pragma pack(pop)

	//��ȡ���뻺����
	TINPUT_BUF* bufInput = (TINPUT_BUF*)(pirp->AssociatedIrp.SystemBuffer);
	//��ȡ�����ڴ�
	ReadPVirtualMemory(bufInput->ProcessID, bufInput->VBaseAddress, bufInput->nSize, bufInput);

	pirp->IoStatus.Information = 4; //����IoStatus��Ϣ����

	if (irpStack)
	{
		if (ntStatus == STATUS_SUCCESS)
		{
			pirp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength; //�����������������
		}
		else
		{
			pirp->IoStatus.Information = 0; //�����������������Ϊ0
		}

		IoCompleteRequest(pirp, IO_NO_INCREMENT); //���IRP����
	}

	pirp->IoStatus.Status = ntStatus; //����IRP״̬
	return ntStatus; //����״̬
}

//д�ڴ�
NTSTATUS IRP_WritePVirtualMemory(PIRP pirp)
{
	KdPrint(("������sys64 %s �к�=%d", __FUNCDNAME__, __LINE__));
	NTSTATUS ntStatus = STATUS_SUCCESS; //��ʼ��״̬Ϊ�ɹ�
	PIO_STACK_LOCATION irpStack = NULL; //��ʼ��IO��ջλ��
	irpStack = IoGetCurrentIrpStackLocation(pirp); //��ȡ��ǰ��IRP��ջλ��

#pragma pack(push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 ProcessID; //Ŀ�����PID
		PVOID VBaseAddress; //Ŀ����������ַ
		UINT32 nSize; //д��ĳ���
		PVOID pBuf; //д������ݵ�ַ
	} TINPUT_BUF;
#pragma pack(pop)

	//��ȡ���뻺����
	TINPUT_BUF* bufInput = (TINPUT_BUF*)(pirp->AssociatedIrp.SystemBuffer);
	//д�������ڴ�
	WritePVirtualMemory(bufInput->ProcessID, bufInput->VBaseAddress, bufInput->nSize, bufInput->pBuf);

	pirp->IoStatus.Information = 4; //����IoStatus��Ϣ����

	if (irpStack)
	{
		if (ntStatus == STATUS_SUCCESS)
		{
			pirp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength; //�����������������
		}
		else
		{
			pirp->IoStatus.Information = 0; //�����������������Ϊ0
		}

		IoCompleteRequest(pirp, IO_NO_INCREMENT); //���IRP����
	}

	pirp->IoStatus.Status = ntStatus; //����IRP״̬
	return ntStatus; //����״̬
}

