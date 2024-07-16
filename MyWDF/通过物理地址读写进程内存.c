#include "ntifs.h"

//物理地址的最大值
UINT64 g_maxPhysAddress = 0;

//获取物理地址的最大值
UINT64 getg_maxPhysAddress(void)
{
	if (g_maxPhysAddress == 0)
	{
		int physicalbits;
		UINT32 r[4]; //存储CPUID指令返回的信息
		__cpuid(r, 0x80000008); //获取物理地址位数
		physicalbits = r[0] & 0xff; //取出前8位的物理地址位数
		g_maxPhysAddress = 0xFFFFFFFFFFFFFFFFULL;
		g_maxPhysAddress = g_maxPhysAddress >> physicalbits; //计算最大物理地址
		g_maxPhysAddress = ~(g_maxPhysAddress << physicalbits); //计算实际的物理地址掩码
	}
	return g_maxPhysAddress; //返回最大物理地址
}

//读取物理内存
BOOLEAN ReadPhysicalMemory(char* physicalBase, UINT_PTR bytestoread, void* output)
{
	HANDLE physmem;
	UNICODE_STRING physmemString;
	OBJECT_ATTRIBUTES attributes;
	const WCHAR* physmemName = L"\\device\\physicalmemory"; //物理内存设备名
	UCHAR* vaddress; //映射后的虚地址
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PMDL outputMDL; //存放读取的数据的MDL

	KdPrint(("驱动 ：ReadPhysicalMemory(%p, %lld, %p)", physicalBase, bytestoread, output));

	if (((UINT64)physicalBase > getg_maxPhysAddress()) || ((UINT64)physicalBase + bytestoread > getg_maxPhysAddress()))
	{
		KdPrint(("驱动 ：SYS Invalid physical address\n"));
		return ntStatus == FALSE; //如果地址无效则返回失败
	}

	outputMDL = IoAllocateMdl(output, (ULONG)bytestoread, FALSE, FALSE, NULL);

	__try
	{
		MmProbeAndLockPages(outputMDL, KernelMode, IoWriteAccess); //锁定内存页，防止被分页出去
	}
	__except (1)
	{
		IoFreeMdl(outputMDL); //解锁内存页
		return FALSE;
	}

	__try
	{
		RtlInitUnicodeString(&physmemString, physmemName); //初始化物理内存设备字符串
		InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL); //初始化对象属性
		ntStatus = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes); //打开物理内存设备

		if (ntStatus == STATUS_SUCCESS)
		{
			SIZE_T length;
			PHYSICAL_ADDRESS viewBase; //物理内存地址
			UINT_PTR offset;
			UINT_PTR toread;

			viewBase.QuadPart = (ULONGLONG)(physicalBase);
			length = 0x2000; //读取长度
			toread = bytestoread;
			vaddress = NULL;

			KdPrint(("驱动 ：ReadPhysicalMemory:viewBase.QuadPart=%x", viewBase.QuadPart));

			//映射物理内存地址到当前进程的虚地址空间
			ntStatus = ZwMapViewOfSection(
				physmem, //物理内存句柄
				NtCurrentProcess(), //当前进程句柄
				&vaddress, //映射后的虚地址
				0L, //零位
				length, //提交大小
				&viewBase, //段偏移
				&length, //视图大小
				ViewShare,
				0,
				PAGE_READWRITE //读写权限
			);

			if ((ntStatus == STATUS_SUCCESS) && (vaddress != NULL))
			{
				if (toread > length)
					toread = length;

				if (toread)
				{
					__try
					{
						offset = (UINT_PTR)(physicalBase)-(UINT_PTR)viewBase.QuadPart; //计算偏移量

						if (offset + toread > length)
						{
							KdPrint(("驱动 ：Too small map"));
							__noop(("驱动 ：Too small map"));
						}
						else
						{
							RtlCopyMemory(output, &vaddress[offset], toread); //拷贝内存数据
						}
						ZwUnmapViewOfSection(NtCurrentProcess(), vaddress); //取消映射
					}
					__except (1)
					{
						KdPrint(("驱动 ：Failure mapping physical memory"));
					}
				}
			}
			else
			{
				KdPrint(("驱动 ：ReadPhysicalMemory error:ntStatus=%x", ntStatus));
			}
			ZwClose(physmem); //关闭物理内存句柄
		}
	}
	__except (1)
	{
		KdPrint(("驱动 ：Error while reading physical memory\n"));
	}

	MmUnlockPages(outputMDL); //解锁内存页
	IoFreeMdl(outputMDL); //释放MDL

	return ntStatus == STATUS_SUCCESS ? TRUE : FALSE; //返回读取结果
}

//写入物理内存
BOOLEAN WritePhysicalMemory(char* physicalBase, IN UINT_PTR nSizeWrite, IN PVOID InBuf)
{
	HANDLE physmem;
	UNICODE_STRING physmemString;
	OBJECT_ATTRIBUTES attributes;
	const WCHAR* physmemName = L"\\device\\physicalmemory"; //物理内存设备名
	UCHAR* vaddress = NULL; //映射后的虚地址
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PMDL pInBufMDL = NULL; //存放写入数据的MDL

	KdPrint(("驱动 ：SYS:WritePhysicalMemory(%p, %lld, %p)", physicalBase, nSizeWrite, InBuf));

	if (((UINT64)physicalBase > getg_maxPhysAddress()) || ((UINT64)physicalBase + nSizeWrite > getg_maxPhysAddress()))
	{
		KdPrint(("驱动 ：SYS:Error Invalid physical address\n"));
		return ntStatus == FALSE; //如果地址无效则返回失败
	}

	//IoAllocateMdl 例程分配内存描述符列表 (MDL) 足以映射缓冲区
	pInBufMDL = IoAllocateMdl(InBuf, (ULONG)nSizeWrite, FALSE, FALSE, NULL);

	__try
	{
		MmProbeAndLockPages(pInBufMDL, KernelMode, IoWriteAccess); //锁定内存页，防止被分页出去
	}
	__except (1)
	{
		IoFreeMdl(pInBufMDL); //释放MDL
		KdPrint(("驱动 ：SYS:Error InBuf MmProbeAndLockPages fail \n"));
		return FALSE;
	}

	PVOID pMapedAddr = NULL;

	__try
	{
		//映射锁定的页到虚拟地址空间
		pMapedAddr = MmMapLockedPagesSpecifyCache(pInBufMDL, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

		if (!pMapedAddr)
		{
			KdPrint(("驱动 ：SYS:pMapedAdd == NULL\n"));
			return 0;
		}
	}
	__except (1)
	{
		KdPrint(("驱动 ：SYS:MmMapLockedPagesSpecifyCache 映射内存失败 pMapedAddr=%p\n", pMapedAddr));
		return 0;
	}

	__try
	{
		RtlInitUnicodeString(&physmemString, physmemName); //初始化物理内存设备字符串
		InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL); //初始化对象属性
		ntStatus = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes); //打开物理内存设备

		if (ntStatus == STATUS_SUCCESS)
		{
			SIZE_T length;
			PHYSICAL_ADDRESS viewBase; //物理内存地址
			UINT_PTR offset;
			UINT_PTR toWriteSize;

			viewBase.QuadPart = (ULONGLONG)(physicalBase);
			length = 0x2000; //写入长度
			toWriteSize = nSizeWrite;
			vaddress = NULL;

			KdPrint(("驱动 ：SYS:ReadPhysicalMemory:地址=%lld", viewBase.QuadPart));

			//映射物理内存地址到当前进程的虚地址空间
			ntStatus = ZwMapViewOfSection(
				physmem, //物理内存句柄
				NtCurrentProcess(), //当前进程句柄
				&vaddress, //映射后的虚地址
				0L, //零位
				length, //提交大小
				&viewBase, //段偏移
				&length, //视图大小
				ViewShare,
				0,
				PAGE_READWRITE //读写权限
			);

			if ((ntStatus == STATUS_SUCCESS) && (vaddress != NULL))
			{
				if (toWriteSize > length)
					toWriteSize = length;

				if (toWriteSize)
				{
					__try
					{
						offset = (UINT_PTR)(physicalBase)-(UINT_PTR)viewBase.QuadPart; //计算偏移量

						if (offset + toWriteSize > length)
						{
							KdPrint(("驱动 ：内存映射太小"));
							__noop(("驱动 ：内存映射太小"));
						}
						else
						{
							RtlCopyMemory(&vaddress[offset], pMapedAddr, toWriteSize); //拷贝数据到内存
						}
						ZwUnmapViewOfSection(NtCurrentProcess(), vaddress); //取消映射
					}
					__except (1)
					{
						KdPrint(("驱动 ：映射物理内存失败"));
					}
				}
			}
			else
			{
				KdPrint(("驱动 ：ReadPhysicalMemory error:ntStatus=%x", ntStatus));
			}
			ZwClose(physmem); //关闭物理内存句柄
		}
	}
	__except (1)
	{
		KdPrint(("驱动 ：读物理内存错误\n"));
	}

	MmUnmapLockedPages(pMapedAddr, pInBufMDL); //取消映射锁定页
	MmUnlockPages(pInBufMDL); //解锁内存页
	IoFreeMdl(pInBufMDL); //释放MDL

	return ntStatus == STATUS_SUCCESS ? TRUE : FALSE; //返回写入结果
}

//获取物理地址
PVOID GetPhysicalAddress(UINT32 ProcessID, PVOID vBaseAddress)
{

	KdPrint(("驱动：开始获取物理地址 ProcessID=%d  vBaseAddress=%p", ProcessID, vBaseAddress));
	PEPROCESS selectedprocess; //存放指定ProcessID的PEPROCESS
	PHYSICAL_ADDRESS physical; //返回的物理地址
	physical.QuadPart = 0; //初始化物理地址
	NTSTATUS ntStatus = STATUS_SUCCESS; //初始化状态为成功

	__try
	{
		//查找指定的进程
		if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(ProcessID), &selectedprocess) == STATUS_SUCCESS)
		{
			KAPC_STATE apc_state; //定义APC状态
			RtlZeroMemory(&apc_state, sizeof(apc_state)); //清零APC状态

			//附加到指定进程的上下文
			KeStackAttachProcess((PVOID)selectedprocess, &apc_state);

			__try
			{
				//将虚拟地址转换为物理地址
				physical = MmGetPhysicalAddress((PVOID)vBaseAddress);
			}
			__finally
			{
				//从指定进程的上下文分离
				KeUnstackDetachProcess(&apc_state);
			}
			//取消对进程对象的引用
			ObDereferenceObject(selectedprocess);
		}
	}
	__except (1)
	{
		ntStatus = STATUS_UNSUCCESSFUL; //捕获异常并设置状态为失败
	}

	//如果状态成功，则返回物理地址
	if (ntStatus == STATUS_SUCCESS)
	{
		return (PVOID)physical.QuadPart;
	}

	return NULL; //否则返回NULL
}

//读虚拟内存
BOOLEAN ReadPVirtualMemory(UINT32 ProcessID, IN PVOID VBaseAddress, IN UINT32 nSize, OUT PVOID pBuf)
{
	KdPrint(("驱动：SYS:WritePVirtualMemory ProcessID= %d,VBaseAddress=%p,nSize=%d,pBuf=%p", ProcessID, VBaseAddress, nSize, pBuf));
	PVOID phyBase = GetPhysicalAddress(ProcessID, VBaseAddress); //获取物理地址

	if (phyBase)
	{
		//读取物理内存
		return ReadPhysicalMemory(phyBase, nSize, pBuf);
	}
	else
	{
		return FALSE; //获取物理地址失败返回FALSE
	}
}

//写虚拟内存
BOOLEAN WritePVirtualMemory(UINT32 ProcessID, IN PVOID VBaseAddress, IN UINT32 nSize, IN PVOID pBuf)
{
	KdPrint(("驱动：SYS:WritePVirtualMemory ProcessID= %d,VBaseAddress=%p,nSize=%d,pBuf=%p", ProcessID, VBaseAddress, nSize, pBuf));
	PVOID phyBase = GetPhysicalAddress(ProcessID, VBaseAddress); //获取物理地址

	if (phyBase)
	{
		//写入物理内存
		return WritePhysicalMemory(phyBase, nSize, pBuf);
	}
	else
	{
		return FALSE; //获取物理地址失败返回FALSE
	}
}

//读内存
NTSTATUS IRP_ReadPVirtualMemory(PIRP pirp)
{
	KdPrint(("驱动：sys64 %s 行号=%d", __FUNCDNAME__, __LINE__));
	NTSTATUS ntStatus = STATUS_SUCCESS; //初始化状态为成功
	PIO_STACK_LOCATION irpStack = NULL; //初始化IO堆栈位置
	irpStack = IoGetCurrentIrpStackLocation(pirp); //获取当前的IRP堆栈位置

#pragma pack(push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 ProcessID; //目标进程PID
		PVOID VBaseAddress; //目标进程虚拟地址
		UINT32 nSize; //读取的长度
		PVOID pBuf; //忽略此字段
	} TINPUT_BUF;
#pragma pack(pop)

	//获取输入缓冲区
	TINPUT_BUF* bufInput = (TINPUT_BUF*)(pirp->AssociatedIrp.SystemBuffer);
	//读取虚拟内存
	ReadPVirtualMemory(bufInput->ProcessID, bufInput->VBaseAddress, bufInput->nSize, bufInput);

	pirp->IoStatus.Information = 4; //设置IoStatus信息长度

	if (irpStack)
	{
		if (ntStatus == STATUS_SUCCESS)
		{
			pirp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength; //设置输出缓冲区长度
		}
		else
		{
			pirp->IoStatus.Information = 0; //设置输出缓冲区长度为0
		}

		IoCompleteRequest(pirp, IO_NO_INCREMENT); //完成IRP请求
	}

	pirp->IoStatus.Status = ntStatus; //设置IRP状态
	return ntStatus; //返回状态
}

//写内存
NTSTATUS IRP_WritePVirtualMemory(PIRP pirp)
{
	KdPrint(("驱动：sys64 %s 行号=%d", __FUNCDNAME__, __LINE__));
	NTSTATUS ntStatus = STATUS_SUCCESS; //初始化状态为成功
	PIO_STACK_LOCATION irpStack = NULL; //初始化IO堆栈位置
	irpStack = IoGetCurrentIrpStackLocation(pirp); //获取当前的IRP堆栈位置

#pragma pack(push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 ProcessID; //目标进程PID
		PVOID VBaseAddress; //目标进程虚拟地址
		UINT32 nSize; //写入的长度
		PVOID pBuf; //写入的数据地址
	} TINPUT_BUF;
#pragma pack(pop)

	//获取输入缓冲区
	TINPUT_BUF* bufInput = (TINPUT_BUF*)(pirp->AssociatedIrp.SystemBuffer);
	//写入虚拟内存
	WritePVirtualMemory(bufInput->ProcessID, bufInput->VBaseAddress, bufInput->nSize, bufInput->pBuf);

	pirp->IoStatus.Information = 4; //设置IoStatus信息长度

	if (irpStack)
	{
		if (ntStatus == STATUS_SUCCESS)
		{
			pirp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength; //设置输出缓冲区长度
		}
		else
		{
			pirp->IoStatus.Information = 0; //设置输出缓冲区长度为0
		}

		IoCompleteRequest(pirp, IO_NO_INCREMENT); //完成IRP请求
	}

	pirp->IoStatus.Status = ntStatus; //设置IRP状态
	return ntStatus; //返回状态
}

