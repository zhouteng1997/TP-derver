#include <Windows.h>
#include "�����ӿ�.h"

#define IO_д���ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_��ȡ�ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define CTL_IO_�����ڴ�д�� CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����
#define CTL_IO_�����ڴ��ȡ CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����

#define IO_�������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ɾ������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_�������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_ͨ�������ȡ���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ͨ�����̱������ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������


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
		UINT32 pid;//Ŀ�����
		PVOID pBase;///Ŀ����̵�ַ
		UINT32 nSize;//Ҫ��ȡ�ĳ���
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF ��������;
	��������.pid = (HANDLE)hProcess; //Ŀ�����ID
	��������.pBase = (PVOID)lpBaseAddress; //Ŀ����̵�ַ
	��������.nSize = (UINT32)nSize;


	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DWORD dwRetSize = 0;//�����ֽ���

	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_��ȡ�ܱ����Ľ���,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);
	//����豸
	return;
}
