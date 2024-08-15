#include <ntifs.h>
#include "hook.h"

static HOOK hook = NULL;

NTSTATUS Initialize();
void Deinitialize();
PVOID GetFunctionAddress(const char* apiname);


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemKernelDebuggerInformation = 35,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

// ���� NtQuerySystemInformation ����ָ������
typedef NTSTATUS(*NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

// ����ԭʼ NtQuerySystemInformation ����ָ��
NtQuerySystemInformation_t OriginalNtQuerySystemInformation;

// ���Ӻ��������� NtQuerySystemInformation ����
NTSTATUS
HookedNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	// ����Ƿ��ǲ�ѯ SystemCodeIntegrityInformation
	if (SystemInformationClass == SystemCodeIntegrityInformation) {
		if (SystemInformationLength >= sizeof(ULONG)) {
			__debugbreak();
			ULONG* codeIntegrityOptions = (ULONG*)SystemInformation;
			// �޸� codeIntegrityOptions �����ز���ǩ��״̬
			*codeIntegrityOptions &= ~0x02; // ��� Bit 1
		}
	}
	// ����ԭʼ�� NtQuerySystemInformation ����
	return OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

// ��������ж�غ���
extern "C" VOID
UnloadDriver(
	PDRIVER_OBJECT DriverObject
) {
	UNREFERENCED_PARAMETER(DriverObject);
	Unhook(hook);
	//��ʼ��ssdt
	Deinitialize();

}

// ����������ں���
extern "C" NTSTATUS
DriverEntry(
	PDRIVER_OBJECT   DriverObject,
	PUNICODE_STRING  RegistryPath
) {
	UNREFERENCED_PARAMETER(RegistryPath);

	// ��ʼ����������
	DriverObject->DriverUnload = UnloadDriver;

	__debugbreak();
	//��ʼ��ssdt
	Initialize();
	// ��ȡ NtQuerySystemInformation ��ַ
	PVOID NtSysifm = GetFunctionAddress("NtQuerySystemInformation");
	//���������ַ
	OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)NtSysifm;
	//hook���������д���Լ����߼�
	hook = Hook(&NtSysifm, (void*)&HookedNtQuerySystemInformation);
	return STATUS_SUCCESS;
}
