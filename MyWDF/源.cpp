//#include <ntimage.h>
#include<ntifs.h>
#include<intrin.h>//打开可写内存的检测

extern void debg();
//关闭写保护
KIRQL WPOFFx64() {
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
//开启写保护
void WPONx64(KIRQL irql) {
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
//这里尝试过tp的双机调试，环境为win10 1903
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//1、首先解决The context is partially valid. Only x86 user-mode context is available. 
/*
nt!KdpTrap:
fffff807`64bfffc8 48895c2408   mov   qword ptr [rsp+8],rbx
fffff807`64bfffcd 4889542410   mov   qword ptr [rsp+10h],rdx
fffff807`64bfffd2 57       push  rdi
fffff807`64bfffd3 4883ec40    sub   rsp,40h
fffff807`64bfffd7 33d2      xor   edx,edx
*/
ULONG64 orgkdt = 0xfffff80166201fc8;
//ULONG64 orgkdt= 0xfffff80764bfffc8;//直接写硬编码,这里需要进行修改<-------------------------------------------------------------------------------------------------------------------------------------------------------
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
extern NTSTATUS hdbktrap(IN PKTRAP_FRAME TrapFrame, IN PKEXCEPTION_FRAME ExceptionFrame, IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN KPROCESSOR_MODE PreviousMode, IN BOOLEAN SecondChanceException);
//这里做一个跳转
VOID ModifyKdpTrap(PVOID myaddress, PVOID targetaddress) {
	KIRQL irql;
	ULONGLONG myfun;
	UCHAR jmp_code[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0\x00\x00";//mov rax xxx,jmp rax
	myfun = (ULONGLONG)myaddress;//替换成自己的函数地址
	RtlCopyMemory(jmp_code + 2, &myfun, 8);
	//debg();
	irql = WPOFFx64();
	RtlCopyMemory(targetaddress, jmp_code, 12);
	WPONx64(irql);
}
//这里完成hook
NTSTATUS HookKdpTrap(
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException) {

	PEPROCESS hp = PsGetCurrentProcess();
	if (!_stricmp((char*)PsGetProcessImageFileName(hp), "TASLogin.exe")) {
		return STATUS_SUCCESS;
	}
	return hdbktrap(TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChanceException);
}
//这里做一个还原
void UnHookKdpTrap() {
	KIRQL irql;
	UCHAR orignal_code[] = "\x48\x89\x5c\x24\x08\x48\x89\x54\x24\x10\x57\x48\x83\xec\x40";//mov rax xxx,jmp rax
	irql = WPOFFx64();
	RtlCopyMemory((PVOID)orgkdt,  orignal_code, 15);
	WPONx64(irql);
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//2、 防止安全组件加载失败
VOID DisableKdDebuggerEnabled() {
	SharedUserData->KdDebuggerEnabled = FALSE; //防止安全组件加载失败
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//3、TP会清零KdDebuggerEnabled,这里做一个每隔一秒的定时器
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//4、断链隐藏 kdcom，防止kdcom内存被清空导致和windbg通讯不了
/*
0: kd> dt _eprocess
nt!_EPROCESS
  +0x000 Pcb       : _KPROCESS
  +0x2e0 ProcessLock   : _EX_PUSH_LOCK
  +0x2e8 UniqueProcessId : Ptr64 Void
  +0x2f0 ActiveProcessLinks : _LIST_ENTRY
*/
PDRIVER_OBJECT pDriverObject = NULL;
typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	ULONG UnKnow;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
VOID HideDriver() {
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	PKLDR_DATA_TABLE_ENTRY firstentry;
	UNICODE_STRING uniDriverName;
	firstentry = entry;
	// 初始化要隐藏驱动的驱动名
	RtlInitUnicodeString(&uniDriverName, L"kdcom.dll");
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry) {
		if (entry->FullDllName.Buffer != 0) {
			if (RtlCompareUnicodeString(&uniDriverName, &(entry->BaseDllName), FALSE) == 0) {
				//DbgPrint("隐藏驱动 %ws 成功!\n", entry->BaseDllName.Buffer);
				// 修改 Flink 和 Blink 指针, 以跳过我们要隐藏的驱动
				*((ULONG*)entry->InLoadOrderLinks.Blink) = (ULONG)entry->InLoadOrderLinks.Flink;
				entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
				/*
				 使被隐藏驱动LIST_ENTRY结构体的Flink, Blink域指向自己
				 因为此节点本来在链表中, 那么它邻接的节点驱动被卸载时,
				 系统会把此节点的Flink, Blink域指向它相邻节点的下一个节点.
				 但是, 它此时已经脱离链表了, 如果现在它原本相邻的节点驱动被
				 卸载了, 那么此节点的Flink, Blink域将有可能指向无用的地址, 而
				 造成随机性的BSoD.
				*/
				entry->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				entry->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				break;
			}
		}
		// 链表往前走
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//5、处理TP蓝屏
/*
fffff807`642d2210 48895c2420   mov   qword ptr [rsp+20h],rbx
fffff807`642d2215 4488442418   mov   byte ptr [rsp+18h],r8b
fffff807`642d221a 56       push  rsi
fffff807`642d221b 57       push  rdi
fffff807`642d221c 4154      push  r12
fffff807`642d221e 4155      push  r13
fffff807`642d2220 4157      push  r15
fffff807`642d2222 4883ec20    sub   rsp,20h
*/
#define KdEnteredDebugger 0xfffff80165d061e0
//#define KdEnteredDebugger 0xfffff80764704100//直接写硬编码,这里需要进行修改<-----------------------------------------------------------------------------------------------------------------------------------------------
extern PMDL hookIoAllocateMdl(__drv_aliasesMem PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
ULONG64 IoAllocateM = 0;
//这里做一个跳转
VOID ModifyIoAllocateMdl(PVOID myaddress, PVOID targetaddress) {
	KIRQL irql;
	ULONGLONG myfun;
	UCHAR jmp_code[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0\x00\x00";//mov rax xxx,jmp rax
	myfun = (ULONGLONG)myaddress;//替换成自己的函数地址
	RtlCopyMemory(jmp_code + 2, &myfun, 8);
	//debg();
	irql = WPOFFx64();
	RtlCopyMemory(targetaddress, jmp_code, 12);
	WPONx64(irql);
}
PMDL newIoAllocateMdl(__drv_aliasesMem PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp) {
	//debg();
	if (VirtualAddress == (PVOID)KdEnteredDebugger) {
		//DbgPrint("[KdEnteredDebugger] address: %p\n", KdEnteredDebugger);
		VirtualAddress = (PUCHAR)KdEnteredDebugger + 0x30; //据暗中观察，+0x30 的位置恒为0
	}
	return hookIoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}
//这里做一个还原
void UnHookIoAllocateMdl() {
	KIRQL irql;
	UCHAR orignal_code[] = "\x48\x89\x5c\x24\x20\x44\x88\x44\x24\x18\x56\x57\x41\x54\x41\x55";
	irql = WPOFFx64();
	RtlCopyMemory(IoAllocateMdl, orignal_code, 15);
	WPONx64(irql);
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	//还原之前的KdpTraphook
	UnHookKdpTrap();
	//还原之前的IoAllocateMdl
	UnHookIoAllocateMdl();
	//取消定时器

	DbgPrint("See You !\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath) {
	pDriverObject = DriverObject;
	DriverObject->DriverUnload = DriverUnload;
	//这里把这个函数进行了hook
	ModifyKdpTrap(HookKdpTrap,(PVOID)orgkdt);
	//防止安全组件加载失败
	DisableKdDebuggerEnabled();
	//摘掉kdcom的eprocess
	HideDriver();
	//干掉TP蓝屏
	IoAllocateM = (ULONG64)IoAllocateMdl;//得到函数的地址
	ModifyIoAllocateMdl(newIoAllocateMdl, IoAllocateMdl);
	//设置定时器
	return STATUS_SUCCESS;
}