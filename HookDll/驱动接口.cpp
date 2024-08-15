#include "pch.h"
#include <Windows.h>
#include "�����ӿ�.h"
#include <cstdio>

#define ���������� L"\\??\\HookDriver"

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

#define IO_д���ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_��ȡ�ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define CTL_IO_�����ڴ�д�� CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����
#define CTL_IO_�����ڴ��ȡ CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����
#define IO_ͨ�������ȡ���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ͨ�����̱������ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ZwQueryVirtualMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_TerminateProcess CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������



namespace TROAPI {
	HANDLE DeviceHandle = nullptr; // ���������豸���;
	HANDLE OpenDevice() {
		DeviceHandle = CreateFileW(
			����������,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		return DeviceHandle;
	}
	HANDLE CloseDevice()
	{
		//�ر��豸
		if (DeviceHandle != NULL)
			CloseHandle(DeviceHandle);
		return HANDLE();
	}

	BOOL WINAPI TROAPI::MyReadProcessMemory(
		_In_ HANDLE hProcess,
		_In_ LPCVOID lpBaseAddress,
		_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,//���մ�Ŀ����̶�ȡ�����ݵĻ�����
		_In_ SIZE_T nSize,//Ҫ��ȡ���ֽ���
		_Out_opt_ SIZE_T* lpNumberOfBytesRead //ʵ�ʶ�ȡ���ֽ���
	)
	{
#pragma pack (push)
#pragma pack(8)
		typedef struct TINPUT_BUF
		{
			UINT64 hProcess;//���
			UINT64 lpBaseAddress;///Ŀ����̵�ַ
			UINT64 lpBuffer;//���մ�Ŀ����̶�ȡ�����ݵĻ�����
			UINT64 nSize;//Ҫ��ȡ���ֽ���
			UINT64 lpNumberOfBytesRead; //ʵ�ʶ�ȡ���ֽ���
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF input = { (UINT64)hProcess ,(UINT64)lpBaseAddress ,(UINT64)lpBuffer ,(UINT64)nSize ,(UINT64)lpNumberOfBytesRead };
		DWORD retSize = sizeof(INT64);
		INT64 ret = 0;//���������
		DeviceIoControl(
			DeviceHandle,//CreateFile�������豸���صľ��
			IO_��ȡ�ܱ����Ľ���,//������CTL_CODE
			&input,//���뻺����ָ��
			sizeof(TINPUT_BUF),//���뻺������С
			&ret,//���ػ�����
			sizeof(ret),//���ػ�������С
			&retSize,//�����ֽ���
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
			UINT64 hProcess;//���
			UINT64 lpBaseAddress;///Ŀ����̵�ַ
			UINT64 lpBuffer;//���մ�Ŀ����̶�ȡ�����ݵĻ�����
			UINT64 nSize;//Ҫ��ȡ���ֽ���
			UINT64 lpNumberOfBytesWritten; //ʵ�ʶ�ȡ���ֽ���
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF input = { (UINT64)hProcess ,(UINT64)lpBaseAddress ,(UINT64)lpBuffer ,(UINT64)nSize ,(UINT64)lpNumberOfBytesWritten };
		DWORD retSize = sizeof(INT64);
		INT64 ret = 0;//���������
		DeviceIoControl(
			DeviceHandle,//CreateFile�������豸���صľ��
			IO_д���ܱ����Ľ���,//������CTL_CODE
			&input,//���뻺����ָ��
			sizeof(TINPUT_BUF),//���뻺������С
			&ret,//���ػ�����
			sizeof(ret),//���ػ�������С
			&retSize,//�����ֽ���
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
			UINT64 hProcess;//���
			UINT64 uExitCode;
		}TINPUT_BUF;
#pragma pack (pop)

		TINPUT_BUF input = { (UINT64)hProcess ,(UINT64)uExitCode};
		DWORD retSize = sizeof(INT64);
		INT64 ret = 0;//���������
		DeviceIoControl(
			DeviceHandle,//CreateFile�������豸���صľ��
			IO_TerminateProcess,//������CTL_CODE
			&input,//���뻺����ָ��
			sizeof(TINPUT_BUF),//���뻺������С
			&ret,//���ػ�����
			sizeof(ret),//���ػ�������С
			&retSize,//�����ֽ���
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
			ULONG64 ProcessHandle;//���
			ULONG64 BaseAddress;///Ŀ����̵�ַ
			ULONG64 MemoryInformationClass;
			ULONG64 MemoryInformation;
			ULONG64 MemoryInformationLength;
			ULONG64 ReturnLength;
		}TINPUT_BUF;
#pragma pack (pop)
		TINPUT_BUF ��������;
		��������.ProcessHandle = (ULONG64)ProcessHandle; //���
		��������.BaseAddress = (ULONG64)BaseAddress; //Ŀ����̵�ַ
		��������.MemoryInformationClass = (ULONG64)MemoryInformationClass;
		��������.MemoryInformation = (ULONG64)MemoryInformation;
		��������.MemoryInformationLength = (ULONG64)MemoryInformationLength;
		��������.ReturnLength = (ULONG64)ReturnLength;

		//���������
		int OutBuf[1] = { 0 };//���������
		DWORD dwRetSize = 0;//�����ֽ���

		//��������
		DeviceIoControl(
			DeviceHandle,//CreateFile�������豸���صľ��
			IO_ZwQueryVirtualMemory,//������CTL_CODE
			&��������,//���뻺����ָ��
			sizeof(TINPUT_BUF),//���뻺������С
			OutBuf,//���ػ�����
			(DWORD)dwRetSize,//���ػ�������С
			&dwRetSize,//�����ֽ���
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
