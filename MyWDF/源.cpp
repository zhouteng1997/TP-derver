//#include <ntimage.h>
#include<ntifs.h>
#include<intrin.h>//�򿪿�д�ڴ�ļ��

extern void debg();
//�ر�д����
KIRQL WPOFFx64() {
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
//����д����
void WPONx64(KIRQL irql) {
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
//���ﳢ�Թ�tp��˫�����ԣ�����Ϊwin10 1903
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//1�����Ƚ��The context is partially valid. Only x86 user-mode context is available. 
/*
nt!KdpTrap:
fffff807`64bfffc8 48895c2408   mov   qword ptr [rsp+8],rbx
fffff807`64bfffcd 4889542410   mov   qword ptr [rsp+10h],rdx
fffff807`64bfffd2 57       push  rdi
fffff807`64bfffd3 4883ec40    sub   rsp,40h
fffff807`64bfffd7 33d2      xor   edx,edx
*/
ULONG64 orgkdt = 0xfffff80166201fc8;
//ULONG64 orgkdt= 0xfffff80764bfffc8;//ֱ��дӲ����,������Ҫ�����޸�<-------------------------------------------------------------------------------------------------------------------------------------------------------
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
extern NTSTATUS hdbktrap(IN PKTRAP_FRAME TrapFrame, IN PKEXCEPTION_FRAME ExceptionFrame, IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN KPROCESSOR_MODE PreviousMode, IN BOOLEAN SecondChanceException);
//������һ����ת
VOID ModifyKdpTrap(PVOID myaddress, PVOID targetaddress) {
	KIRQL irql;
	ULONGLONG myfun;
	UCHAR jmp_code[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0\x00\x00";//mov rax xxx,jmp rax
	myfun = (ULONGLONG)myaddress;//�滻���Լ��ĺ�����ַ
	RtlCopyMemory(jmp_code + 2, &myfun, 8);
	//debg();
	irql = WPOFFx64();
	RtlCopyMemory(targetaddress, jmp_code, 12);
	WPONx64(irql);
}
//�������hook
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
//������һ����ԭ
void UnHookKdpTrap() {
	KIRQL irql;
	UCHAR orignal_code[] = "\x48\x89\x5c\x24\x08\x48\x89\x54\x24\x10\x57\x48\x83\xec\x40";//mov rax xxx,jmp rax
	irql = WPOFFx64();
	RtlCopyMemory((PVOID)orgkdt,  orignal_code, 15);
	WPONx64(irql);
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//2�� ��ֹ��ȫ�������ʧ��
VOID DisableKdDebuggerEnabled() {
	SharedUserData->KdDebuggerEnabled = FALSE; //��ֹ��ȫ�������ʧ��
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//3��TP������KdDebuggerEnabled,������һ��ÿ��һ��Ķ�ʱ��
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//4���������� kdcom����ֹkdcom�ڴ汻��յ��º�windbgͨѶ����
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
	// ��ʼ��Ҫ����������������
	RtlInitUnicodeString(&uniDriverName, L"kdcom.dll");
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry) {
		if (entry->FullDllName.Buffer != 0) {
			if (RtlCompareUnicodeString(&uniDriverName, &(entry->BaseDllName), FALSE) == 0) {
				//DbgPrint("�������� %ws �ɹ�!\n", entry->BaseDllName.Buffer);
				// �޸� Flink �� Blink ָ��, ����������Ҫ���ص�����
				*((ULONG*)entry->InLoadOrderLinks.Blink) = (ULONG)entry->InLoadOrderLinks.Flink;
				entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
				/*
				 ʹ����������LIST_ENTRY�ṹ���Flink, Blink��ָ���Լ�
				 ��Ϊ�˽ڵ㱾����������, ��ô���ڽӵĽڵ�������ж��ʱ,
				 ϵͳ��Ѵ˽ڵ��Flink, Blink��ָ�������ڽڵ����һ���ڵ�.
				 ����, ����ʱ�Ѿ�����������, ���������ԭ�����ڵĽڵ�������
				 ж����, ��ô�˽ڵ��Flink, Blink���п���ָ�����õĵ�ַ, ��
				 �������Ե�BSoD.
				*/
				entry->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				entry->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				break;
			}
		}
		// ������ǰ��
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
//5������TP����
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
//#define KdEnteredDebugger 0xfffff80764704100//ֱ��дӲ����,������Ҫ�����޸�<-----------------------------------------------------------------------------------------------------------------------------------------------
extern PMDL hookIoAllocateMdl(__drv_aliasesMem PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp);
ULONG64 IoAllocateM = 0;
//������һ����ת
VOID ModifyIoAllocateMdl(PVOID myaddress, PVOID targetaddress) {
	KIRQL irql;
	ULONGLONG myfun;
	UCHAR jmp_code[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0\x00\x00";//mov rax xxx,jmp rax
	myfun = (ULONGLONG)myaddress;//�滻���Լ��ĺ�����ַ
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
		VirtualAddress = (PUCHAR)KdEnteredDebugger + 0x30; //�ݰ��й۲죬+0x30 ��λ�ú�Ϊ0
	}
	return hookIoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}
//������һ����ԭ
void UnHookIoAllocateMdl() {
	KIRQL irql;
	UCHAR orignal_code[] = "\x48\x89\x5c\x24\x20\x44\x88\x44\x24\x18\x56\x57\x41\x54\x41\x55";
	irql = WPOFFx64();
	RtlCopyMemory(IoAllocateMdl, orignal_code, 15);
	WPONx64(irql);
}
//----------------------------------------------------------------------------------------------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	//��ԭ֮ǰ��KdpTraphook
	UnHookKdpTrap();
	//��ԭ֮ǰ��IoAllocateMdl
	UnHookIoAllocateMdl();
	//ȡ����ʱ��

	DbgPrint("See You !\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath) {
	pDriverObject = DriverObject;
	DriverObject->DriverUnload = DriverUnload;
	//������������������hook
	ModifyKdpTrap(HookKdpTrap,(PVOID)orgkdt);
	//��ֹ��ȫ�������ʧ��
	DisableKdDebuggerEnabled();
	//ժ��kdcom��eprocess
	HideDriver();
	//�ɵ�TP����
	IoAllocateM = (ULONG64)IoAllocateMdl;//�õ������ĵ�ַ
	ModifyIoAllocateMdl(newIoAllocateMdl, IoAllocateMdl);
	//���ö�ʱ��
	return STATUS_SUCCESS;
}