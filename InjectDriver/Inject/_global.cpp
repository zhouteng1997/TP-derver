#include "_global.h"


void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
	void* Result = ExAllocatePoolZero(NonPagedPool, InSize, 'HIDE');
	if (InZeroMemory && (Result != NULL))
		RtlZeroMemory(Result, InSize);
	return Result;
}


void RtlFreeMemory(void* InPointer)
{
	ExFreePool(InPointer);
}

//Based on: http://leguanyuan.blogspot.nl/2013/09/x64-inline-hook-zwcreatesection.html

NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
	if (!g_pmdl)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(g_pmdl);
	unsigned int* Mapped = (unsigned int*)MmMapLockedPagesSpecifyCache(
		g_pmdl,             // 指向MDL的指针
		KernelMode,      // 访问模式 (KernelMode 或 UserMode)
		MmCached,        // 缓存类型 (例如 MmCached, MmNonCached, MmWriteCombined)
		NULL,            // 基础地址 (NULL 表示让系统选择)
		FALSE,           // 是否是分配专用地址空间
		NormalPagePriority // 页面优先级
	);

	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return STATUS_UNSUCCESSFUL;
	}
	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Mapped, Source, Length);
	KeLowerIrql(kirql);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
	return STATUS_SUCCESS;
}