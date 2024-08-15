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

// 定义 NtQuerySystemInformation 函数指针类型
typedef NTSTATUS(*NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

// 声明原始 NtQuerySystemInformation 函数指针
NtQuerySystemInformation_t OriginalNtQuerySystemInformation;

// 钩子函数：拦截 NtQuerySystemInformation 调用
NTSTATUS
HookedNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) {
	// 检查是否是查询 SystemCodeIntegrityInformation
	if (SystemInformationClass == SystemCodeIntegrityInformation) {
		if (SystemInformationLength >= sizeof(ULONG)) {
			__debugbreak();
			ULONG* codeIntegrityOptions = (ULONG*)SystemInformation;
			// 修改 codeIntegrityOptions 以隐藏测试签名状态
			*codeIntegrityOptions &= ~0x02; // 清除 Bit 1
		}
	}
	// 调用原始的 NtQuerySystemInformation 函数
	return OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

// 驱动程序卸载函数
extern "C" VOID
UnloadDriver(
	PDRIVER_OBJECT DriverObject
) {
	UNREFERENCED_PARAMETER(DriverObject);
	Unhook(hook);
	//初始化ssdt
	Deinitialize();

}

// 驱动程序入口函数
extern "C" NTSTATUS
DriverEntry(
	PDRIVER_OBJECT   DriverObject,
	PUNICODE_STRING  RegistryPath
) {
	UNREFERENCED_PARAMETER(RegistryPath);

	// 初始化驱动程序
	DriverObject->DriverUnload = UnloadDriver;

	__debugbreak();
	//初始化ssdt
	Initialize();
	// 获取 NtQuerySystemInformation 地址
	PVOID NtSysifm = GetFunctionAddress("NtQuerySystemInformation");
	//保存这个地址
	OriginalNtQuerySystemInformation = (NtQuerySystemInformation_t)NtSysifm;
	//hook这个函数，写入自己的逻辑
	hook = Hook(&NtSysifm, (void*)&HookedNtQuerySystemInformation);
	return STATUS_SUCCESS;
}
