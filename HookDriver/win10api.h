#include <ntifs.h>
NTSTATUS ZwQueryInformationProcess(
	IN HANDLE ProcessHandle, // 进程句柄
	IN PROCESSINFOCLASS InformationClass, // 信息类型
	OUT PVOID ProcessInformation, // 缓冲指针
	IN ULONG ProcessInformationLength, // 以字节为单位的缓冲大小
	OUT PULONG ReturnLength OPTIONAL // 写入缓冲的字节数
);
HANDLE HandleToPid(IN HANDLE ProcessID, IN HANDLE handle);