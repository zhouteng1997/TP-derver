#include "pch.h"
#include <Windows.h>
#include "驱动接口.h"
#include <cstdio>

#define 符号链接名 L"\\??\\HookDriver"

#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3
#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define IO_写入受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_读取受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define CTL_IO_物理内存写入 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试
#define CTL_IO_物理内存读取 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试
#define IO_通过句柄获取对象 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_通过进程遍历句柄 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_ZwQueryVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_TerminateProcess CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试



namespace TROAPI {
	HANDLE DeviceHandle = nullptr; // 定义驱动设备句柄;
	HANDLE OpenDevice() {
		DeviceHandle = CreateFileW(
			符号链接名,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		return DeviceHandle;
	}
	HANDLE CloseDevice()
	{
		//关闭设备
		if (DeviceHandle != NULL)
			CloseHandle(DeviceHandle);
		return HANDLE();
	}

	BOOL WINAPI TROAPI::MyReadProcessMemory(
		_In_ HANDLE hProcess,
		_In_ LPCVOID lpBaseAddress,
		_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,//接收从目标进程读取的数据的缓冲区
		_In_ SIZE_T nSize,//要读取的字节数
		_Out_opt_ SIZE_T* lpNumberOfBytesRead //实际读取的字节数
	)
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

		TINPUT_BUF input = { (UINT64)hProcess ,(UINT64)lpBaseAddress ,(UINT64)lpBuffer ,(UINT64)nSize ,(UINT64)lpNumberOfBytesRead };
		DWORD retSize = sizeof(INT64);
		INT64 ret = 0;//输出缓冲区
		DeviceIoControl(
			DeviceHandle,//CreateFile打开驱动设备返回的句柄
			IO_读取受保护的进程,//控制码CTL_CODE
			&input,//输入缓冲区指针
			sizeof(TINPUT_BUF),//输入缓冲区大小
			&ret,//返回缓冲区
			sizeof(ret),//返回缓冲区大小
			&retSize,//返回字节数
			NULL);
		if (ret == 1)
			return TRUE;
		return FALSE;
	}

	BOOL WINAPI TROAPI::MyWriteProcessMemory(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	) {
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			UINT64 hProcess;//句柄
			UINT64 lpBaseAddress;///目标进程地址
			UINT64 lpBuffer;//接收从目标进程读取的数据的缓冲区
			UINT64 nSize;//要读取的字节数
			UINT64 lpNumberOfBytesWritten; //实际读取的字节数
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF input = { (UINT64)hProcess ,(UINT64)lpBaseAddress ,(UINT64)lpBuffer ,(UINT64)nSize ,(UINT64)lpNumberOfBytesWritten };
		DWORD retSize = sizeof(INT64);
		INT64 ret = 0;//输出缓冲区
		DeviceIoControl(
			DeviceHandle,//CreateFile打开驱动设备返回的句柄
			IO_写入受保护的进程,//控制码CTL_CODE
			&input,//输入缓冲区指针
			sizeof(TINPUT_BUF),//输入缓冲区大小
			&ret,//返回缓冲区
			sizeof(ret),//返回缓冲区大小
			&retSize,//返回字节数
			NULL);
		if (ret == 1)
			return TRUE;
		return FALSE;
	}

	BOOL WINAPI TROAPI::MyTerminateProcess(
		_In_ HANDLE hProcess,
		_In_ UINT uExitCode
	) {
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			UINT64 hProcess;//句柄
			UINT64 uExitCode;
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF input = { (UINT64)hProcess ,(UINT64)uExitCode};
		DWORD retSize = sizeof(INT64);
		INT64 ret = 0;//输出缓冲区
		DeviceIoControl(
			DeviceHandle,//CreateFile打开驱动设备返回的句柄
			IO_TerminateProcess,//控制码CTL_CODE
			&input,//输入缓冲区指针
			sizeof(TINPUT_BUF),//输入缓冲区大小
			&ret,//返回缓冲区
			sizeof(ret),//返回缓冲区大小
			&retSize,//返回字节数
			NULL);
		if (ret == 1)
			return TRUE;
		return FALSE;
	}


	BOOL WINAPI TROAPI::MyZwQueryVirtualMemory(
		_In_		HANDLE                   ProcessHandle,
		_In_opt_	PVOID                    BaseAddress,
		_In_		MEMORY_INFORMATION_CLASS MemoryInformationClass,
		_Out_		PVOID                    MemoryInformation,
		_In_		SIZE_T                   MemoryInformationLength,
		_Out_opt_	PSIZE_T                  ReturnLength
	) {
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			ULONG64 ProcessHandle;//句柄
			ULONG64 BaseAddress;///目标进程地址
			ULONG64 MemoryInformationClass;
			ULONG64 MemoryInformation;
			ULONG64 MemoryInformationLength;
			ULONG64 ReturnLength;
		}TINPUT_BUF;
#pragma pack (pop)
		TINPUT_BUF 传入数据;
		传入数据.ProcessHandle = (ULONG64)ProcessHandle; //句柄
		传入数据.BaseAddress = (ULONG64)BaseAddress; //目标进程地址
		传入数据.MemoryInformationClass = (ULONG64)MemoryInformationClass;
		传入数据.MemoryInformation = (ULONG64)MemoryInformation;
		传入数据.MemoryInformationLength = (ULONG64)MemoryInformationLength;
		传入数据.ReturnLength = (ULONG64)ReturnLength;

		//输出缓冲区
		int OutBuf[1] = { 0 };//输出缓冲区
		DWORD dwRetSize = 0;//返回字节数

		//调用驱动
		DeviceIoControl(
			DeviceHandle,//CreateFile打开驱动设备返回的句柄
			IO_ZwQueryVirtualMemory,//控制码CTL_CODE
			&传入数据,//输入缓冲区指针
			sizeof(TINPUT_BUF),//输入缓冲区大小
			OutBuf,//返回缓冲区
			(DWORD)dwRetSize,//返回缓冲区大小
			&dwRetSize,//返回字节数
			NULL);
		//if (dwRetSize) {
		//	__try {
		//		*(DWORD*)lpNumberOfBytesRead = dwRetSize;
		//	}
		//	__except (1)
		//	{
		//		return false;
		//	}
		//}
		return true;
	}

}
