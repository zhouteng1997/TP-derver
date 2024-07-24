#include <Windows.h>
#include "驱动接口.h"

#define IO_写入受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_读取受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define CTL_IO_物理内存写入 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试
#define CTL_IO_物理内存读取 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试

#define IO_添加需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_删除需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_清空需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_通过句柄获取对象 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_通过进程遍历句柄 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试


BOOL WINAPI ReadProcessMemory(
	[in]  HANDLE  hProcess,
	[in]  LPCVOID lpBaseAddress,
	[out] LPVOID  lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T* lpNumberOfBytesRead
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
	传入数据.pid = (HANDLE)hProcess; //目标进程ID
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
	return;
}
