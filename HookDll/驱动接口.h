
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

namespace TROAPI {
    extern HANDLE DeviceHandle; // 声明驱动设备句柄
    HANDLE OpenDevice();
    HANDLE CloseDevice();
    BOOL WINAPI MyReadProcessMemory(
		_In_ HANDLE hProcess,
		_In_ LPCVOID lpBaseAddress,
		_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesRead
    );
	BOOL WINAPI MyWriteProcessMemory(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	);

	BOOL WINAPI MyTerminateProcess(
		_In_ HANDLE hProcess,
		_In_ UINT uExitCode
	);

	BOOL WINAPI MyZwQueryVirtualMemory(
		_In_		HANDLE                   ProcessHandle,
		_In_opt_	PVOID                    BaseAddress,
		_In_		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_		PVOID                    MemoryInformation,
		_In_		SIZE_T                   MemoryInformationLength,
		_Out_opt_	PSIZE_T                  ReturnLength
	);
}