#include "D035-NtDefs.h"
#include <TlHelp32.h> 
#include <comdef.h>


long GetProcessIdFromName(const char* name)
{
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	PROCESSENTRY32 processer;
	processer.dwSize = sizeof(PROCESSENTRY32);

	int flag = Process32First(hsnapshot, &processer);
	while (flag != 0)
	{
		_bstr_t processName(processer.szExeFile);  //WCHAR字符串转换成CHAR字符串
		if (strcmp(processName, name) == 0)
		{
			return processer.th32ProcessID;        //返回进程ID
		}
		flag = Process32Next(hsnapshot, &processer);
	}

	CloseHandle(hsnapshot);
	return -2;
}

//进程句柄转PID
DWORD HandleToPid(IN HANDLE hProcess)
{
	_PROCESS_BASIC_INFORMATION pbi = { 0 };
#define ProcessBasicInformation 0

	NTSTATUS status = NtQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		(PVOID)&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL);
	if (!status)
	{
		return (DWORD)pbi.UniqueProcessId;
	}
	return 0;
}


void GetSystemHandleInformation(NTDEFS::SYSTEM_HANDLE_INFORMATION* pshi)//16
{

	printf("GetSystemHandleInformation 句柄数量=%d\n", pshi->NumberOfHandles); //一般有几万个
	NTDEFS::OBJECT_NAME_INFORMATION* szName = (NTDEFS::OBJECT_NAME_INFORMATION*)malloc(1000);
	NTDEFS::OBJECT_NAME_INFORMATION* szType = (NTDEFS::OBJECT_NAME_INFORMATION*)malloc(1000);
	//查找CE进程id
	long cePid = GetProcessIdFromName("82640.exe");  //输入进程名
	printf("%d ", pshi->NumberOfHandles);
	UINT s = 0;
	for (UINT i = 0; i < pshi->NumberOfHandles; i++)
	{
		if (pshi->Handles[i].UniqueProcessId == cePid)
		{
			HANDLE newHandle = NULL;
			DWORD dwFlags1 = 0;
			DWORD dwFlags2 = 0;
			HANDLE hSourceProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pshi->Handles[i].UniqueProcessId);
			DuplicateHandle(
				hSourceProcessHandle,
				(HANDLE)pshi->Handles[i].HandleValue,
				GetCurrentProcess(),
				&newHandle,
				DUPLICATE_SAME_ACCESS,
				FALSE,
				DUPLICATE_SAME_ACCESS);
			if (newHandle)
			{


				NTSTATUS status1 = NtQueryObject(newHandle, NTDEFS::ObjectNameInformation, szName, 1000, &dwFlags1);
				NTSTATUS status2 = NtQueryObject(newHandle, NTDEFS::ObjectTypeInformation, szType, 1000, &dwFlags2);
				status1;
				status2;

				//if (status2 == 0 && status1==0)
				{
					if (_wcsicmp(szType->Name.Buffer, L"Process") == 0)
					{
						DWORD 句柄目标进程PID = HandleToPid(newHandle);
						if (句柄目标进程PID != pshi->Handles[i].UniqueProcessId && 句柄目标进程PID != 0)
							printf("<szType=%p szName=%p> Process句柄=%X  所属进程=%d 句柄目标进程PID=%d\n\n",
								szType->Name.Buffer,
								szName->Name.Buffer,
								pshi->Handles[i].HandleValue,
								pshi->Handles[i].UniqueProcessId,
								句柄目标进程PID);

						//这是注入模块的句柄
						//pshi->Handles[i].HandleValue,
					}
				}
			}
		}
		s = i;
	}
	printf("循环了 %d", s);
	free(szName);
	free(szType);
}

void 遍历进程句柄() // 定义遍历进程句柄的函数
{
	NTSTATUS status = STATUS_SUCCESS; // 初始化状态为成功
	ULONG retlen = 0; // 用于存储返回的长度
	ULONG SystemInformationLength = 0; // 用于存储系统信息的长度

	// 第一次调用NtQuerySystemInformation，获取所需的缓冲区大小
	status = NtQuerySystemInformation(NTDEFS::SystemHandleInformation, nullptr, 0, &retlen);
	HLOCAL hMem = LocalAlloc(0, retlen); // 根据返回的长度分配内存
	printf("retlen=%X hMem=%p\n", retlen, hMem); // 打印返回长度和分配的内存指针
	if (hMem) // 如果内存分配成功
	{
		NTDEFS::SYSTEM_HANDLE_INFORMATION* pHandleInfo = (NTDEFS::SYSTEM_HANDLE_INFORMATION*)LocalLock(hMem); // 锁定内存，并获取指向该内存的指针
		if (pHandleInfo) // 如果内存锁定成功
		{
			memset(pHandleInfo, 0, retlen); // 将内存初始化为0
			status = NtQuerySystemInformation(NTDEFS::SystemHandleInformation, pHandleInfo, retlen, &retlen); // 第二次调用NtQuerySystemInformation，获取系统句柄信息

			int cs = 0;
			//循环获取内存，直到status为0才算成功,或者100次都失败了
			while (status == STATUS_INFO_LENGTH_MISMATCH || cs>100) // 如果状态仍为STATUS_INFO_LENGTH_MISMATCH
			{
				LocalUnlock(hMem); // 解锁内存
				LocalFree(hMem); // 释放内存

				hMem = LocalAlloc(0, retlen); // 重新分配更大的内存
				if (!hMem) // 如果内存分配失败
				{
					printf("Memory allocation failed");
					return;
				}

				pHandleInfo = (NTDEFS::SYSTEM_HANDLE_INFORMATION*)LocalLock(hMem); // 再次锁定内存，并获取指向该内存的指针
				if (!pHandleInfo) // 如果内存锁定失败
				{
					printf("Memory lock failed");
					LocalFree(hMem); // 释放内存
					return;
				}

				memset(pHandleInfo, 0, retlen); // 将内存初始化为0
				status = NtQuerySystemInformation(NTDEFS::SystemHandleInformation, pHandleInfo, retlen, &retlen); // 重新调用NtQuerySystemInformation
				cs++;
			}

			if (NT_SUCCESS(status)) // 如果调用成功
			{
				GetSystemHandleInformation(pHandleInfo); // 调用函数处理系统句柄信息
			}
			else // 如果调用失败
			{
				printf("NtQuerySystemInformation2 GetLastError %d", GetLastError());
			}
		}
		LocalUnlock(hMem); // 解锁内存
		LocalFree(hMem); // 释放分配的内存
	}
	return; // 返回
}


typedef union _EXHANDLE {
	struct {
		ULONG64 TagBits : 2;
		ULONG64 Index : 30;
	}name1;
	PVOID GenericHandleOverlay;
	ULONG64 Value;
} EXHANDLE, * PEXHANDLE;

int main()
{
	HANDLE handle = (HANDLE)0x4e;
	EXHANDLE b;
	b.Value = (ULONG64)handle;

	//HANDLE hSourceProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 38256);
	遍历进程句柄();
	return 1;
}


