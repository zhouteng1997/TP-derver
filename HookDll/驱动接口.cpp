#include "pch.h"
#include <Windows.h>
#include "驱动接口.h"

#define 符号链接名 L"\\??\\MyDriver"

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

namespace TROAPI {
	HANDLE DeviceHandle= nullptr; // 定义驱动设备句柄;
	HANDLE TROAPI::OpenDevice() {
		DeviceHandle = CreateFileW(
			符号链接名,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		return DeviceHandle;
	}

	BOOL WINAPI TROAPI::ReadProcessMemory(
		IN  HANDLE  hProcess,
		IN  LPCVOID lpBaseAddress,
		OUT LPVOID  lpBuffer,
		IN  SIZE_T  nSize,
		OUT SIZE_T* lpNumberOfBytesRead
	)
	{
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			UINT32 pid;//目标进程
			PVOID pBase;///目标进程地址
			UINT32 nSize;//要读取的长度
		}TINPUT_BUF;
#pragma pack (pop)
		TINPUT_BUF 传入数据;
		传入数据.pid = (UINT32)hProcess; //目标进程ID
		传入数据.pBase = (PVOID)lpBaseAddress; //目标进程地址
		传入数据.nSize = (UINT32)nSize;


		//写入缓冲区
		int OutBuf[1] = { 0 };//输出缓冲区
		DWORD dwRetSize = 0;//返回字节数

		DeviceIoControl(
			DeviceHandle,//CreateFile打开驱动设备返回的句柄
			IO_读取受保护的进程,//控制码CTL_CODE

			&传入数据,//输入缓冲区指针
			sizeof(传入数据),//输入缓冲区大小

			&OutBuf,//返回缓冲区
			sizeof(OutBuf),//返回缓冲区大小

			&dwRetSize,//返回字节数
			NULL);
		//输出设备
		return true;
	}
}
