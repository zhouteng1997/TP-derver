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

		if (diff<len && dest>src)//重叠并且目标地址大于源地址 ，需要反方向复制
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
//读取进程内存的函数
NTSTATUS ReadProcessMemory2(
	IN PEPROCESS pep,    //目标进程
	IN PVOID lpBaseAddress,        //要读取的地址
	IN PVOID lpBuffer,      //存放读取数据的缓冲区
	IN UINT32 nSize,        //要读取的数据长度
	IN UINT_PTR lpNumberOfBytesRead        //读取的数据长度
) {
	pep;
	lpBaseAddress;
	lpBuffer;
	nSize;
	lpNumberOfBytesRead;

	KdPrint(("驱动 ReadProcessMemory2 lpBaseAddress=%p,lpBuffer=%p,nSize=%x,lpNumberOfBytesRead=%x \n",
		lpBaseAddress, lpBuffer, nSize, (UINT32)lpNumberOfBytesRead));  //打印错误信息

	if (!IsOkReadPtr(PR((UINT_PTR)lpBuffer)))//如果这个内存不允许访问
		return STATUS_UNSUCCESSFUL;

	UINT64 num = 0;
	NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
	KAPC_STATE apc_state;
	RtlZeroMemory(&apc_state, sizeof(KAPC_STATE));//分配空间

	PMDL mdl = IoAllocateMdl(lpBuffer, nSize, FALSE, FALSE, NULL);//映射mdl
	if (!mdl)
	{
		return STATUS_UNSUCCESSFUL;
	}
	MmBuildMdlForNonPagedPool(mdl);//标记未分页
	unsigned char* lpBuffer_Mapper = (unsigned char*)MmMapLockedPages(mdl, KernelMode);//映射到内核

	if (!lpBuffer_Mapper)
	{
		IoFreeMdl(mdl);
		return STATUS_UNSUCCESSFUL;
	}

	KeStackAttachProcess(pep, &apc_state);//切换至目标进程


	if (IsOkReadPtr((UINT_PTR)lpBaseAddress))
	{
		__try {
			num = mymemcpy_s((char*)lpBuffer_Mapper, (const char*)lpBaseAddress, (size_t)nSize);
			retStatus = STATUS_SUCCESS;
		}
		__except (1) {}
	}


	KeUnstackDetachProcess(&apc_state);//分离目标进程
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
		PEPROCESS pep = NULL;  //目标进程指针
		if (PsLookupProcessByProcessId(pid, &pep) == STATUS_SUCCESS) {  //查找进程
			retStatus = ReadProcessMemory2(pep, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);  //读取进程内存
			ObDereferenceObject(pep);  //取消引用进程对象
		}
		return retStatus;
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}
}

//处理 IRP 读取进程内存
NTSTATUS IRP_ReadProcessMemory(PIRP pirp) {
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	irpStack;
	UINT64* 缓冲区 = (UINT64*)(pirp->AssociatedIrp.SystemBuffer);
	if (缓冲区)
	{
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			UINT64 hProcess;//句柄
			UINT64 lpBaseAddress;///目标进程地址
			UINT64 lpBuffer;//接收从目标进程读取的数据的缓冲区
			UINT64 nSize;//要读取的字节数
			UINT64 lpNumberOfBytesRead; //实际读取的字节数
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF* input = (TINPUT_BUF*)缓冲区;  //获取输入缓冲区
		INT64* ret = (INT64*)缓冲区;
		NTSTATUS retStatus = ReadProcessMemoryForHandle((HANDLE)input->hProcess, (PVOID)input->lpBaseAddress,
			(PVOID)input->lpBuffer, (UINT32)input->nSize, (UINT_PTR)input->lpNumberOfBytesRead);  //读取进程内存


		if (NT_SUCCESS(retStatus))
		{
			*ret = 1;
			pirp->IoStatus.Status = STATUS_SUCCESS;
			pirp->IoStatus.Information = sizeof(INT64);  //设置返回缓冲区大小
		}
		else {
			*ret = 0;
			pirp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			pirp->IoStatus.Information = sizeof(INT64);  //设置返回缓冲区大小
		}
		IoCompleteRequest(pirp, IO_NO_INCREMENT);  //完成请求
	}
	return STATUS_SUCCESS;  //返回状态
}
