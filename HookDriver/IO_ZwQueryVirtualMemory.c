#include "IO_ZwQueryVirtualMemory.h"
#include "win10api.h"

//读取进程内存的函数
NTSTATUS ZwQueryVirtualMemory2(
	IN PEPROCESS Process,    //目标进程
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
) {

	__debugbreak();

	//映射mdl
	PMDL pmdl_MemoryInformation = IoAllocateMdl(MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION), 0, 0, NULL);
	PMDL pmdl_ReturnLength = IoAllocateMdl(ReturnLength, 8, 0, 0, NULL);

	unsigned char* Mapped_MemoryInformation = {0};
	PSIZE_T Mapped_ReturnLength=0;

	//映射内核
	if (MemoryInformation)
	{
		MmBuildMdlForNonPagedPool(pmdl_MemoryInformation);
		unsigned char* Mapped_MemoryInformation1 = (unsigned char*)MmMapLockedPages(pmdl_MemoryInformation, KernelMode);
		Mapped_MemoryInformation = Mapped_MemoryInformation1;
	}
	//映射内核
	if (pmdl_ReturnLength)
	{
		MmBuildMdlForNonPagedPool(pmdl_ReturnLength);
		PSIZE_T Mapped_ReturnLength1 = (PSIZE_T)MmMapLockedPages(pmdl_ReturnLength, KernelMode);
		Mapped_ReturnLength = Mapped_ReturnLength1;
	}

	//附加进程
	KAPC_STATE apc_state;
	KeStackAttachProcess((PVOID)Process, &apc_state);
	//调用ZwQueryVirtualMemory
	if(Mapped_MemoryInformation && Mapped_ReturnLength)
	ZwQueryVirtualMemory(NtCurrentProcess(), BaseAddress, MemoryInformationClass,
		(PVOID)Mapped_MemoryInformation, MemoryInformationLength, (PSIZE_T)Mapped_ReturnLength);
	//从目标进程分离
	KeUnstackDetachProcess(&apc_state);


	//取消 MDL 的内存映射
	if (Mapped_MemoryInformation && pmdl_MemoryInformation)
		MmUnmapLockedPages((PVOID)Mapped_MemoryInformation, pmdl_MemoryInformation);
	//释放 MDL
	if (pmdl_MemoryInformation)
		IoFreeMdl(pmdl_MemoryInformation);
	//取消 MDL 的内存映射
	if (Mapped_ReturnLength && pmdl_ReturnLength)
		MmUnmapLockedPages((PVOID)Mapped_ReturnLength, pmdl_ReturnLength);
	//释放 MDL
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
	//获取pid
	HANDLE pid = HandleToPid(PsGetCurrentProcessId(), ProcessHandle);
	//定义pep
	PEPROCESS Seleted_pEPROCESS = NULL;  //目标进程指针 pep
	//拿到pep
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)(pid), &Seleted_pEPROCESS)))
		KdPrint(("驱动 sys64 PsLookupProcessByProcessId 失败\n"));  //打印错误信息
	//进入自己写的ZwQueryVirtualMemory
	NTSTATUS result = ZwQueryVirtualMemory2(Seleted_pEPROCESS, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);  //读取进程内存
	//取消引用进程对象
	ObDereferenceObject(Seleted_pEPROCESS);
	//返回
	return result;
}

//处理 IRP 读取进程内存
NTSTATUS IRP_ZwQueryVirtualMemory(PIRP pirp) {
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	irpStack;
	UINT64* 缓冲区 = (UINT64*)(pirp->AssociatedIrp.SystemBuffer);
	if (缓冲区)
	{
#pragma pack(push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			HANDLE                   ProcessHandle;//句柄
			PVOID                    BaseAddress;///目标进程地址
			MEMORY_INFORMATION_CLASS MemoryInformationClass;
			PVOID                    MemoryInformation;
			SIZE_T                   MemoryInformationLength;
			PSIZE_T                  ReturnLength;
		}TINPUT_BUF;
#pragma pack (pop)
		TINPUT_BUF* bufInput = (TINPUT_BUF*)缓冲区;  //获取输入缓冲区

		NTSTATUS result = ZwQueryVirtualMemoryForHandle(bufInput->ProcessHandle, bufInput->BaseAddress, bufInput->MemoryInformationClass,
			bufInput->MemoryInformation, bufInput->MemoryInformationLength, bufInput->ReturnLength);  //读取进程内存


		UINT64* 输出缓冲区 = 缓冲区;
		输出缓冲区[0] = result;

		if (NT_SUCCESS(result))
		{
			pirp->IoStatus.Status = STATUS_SUCCESS;
			pirp->IoStatus.Information = sizeof(UINT64);  //设置返回缓冲区大小
			IoCompleteRequest(pirp, IO_NO_INCREMENT);  //完成请求
			return STATUS_SUCCESS;
		}
		else {
			return -1;
		}
	}
	return -1;  //返回状态
}
