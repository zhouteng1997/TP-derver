#include <ntifs.h>
NTSTATUS ZwQueryInformationProcess(
	IN HANDLE ProcessHandle, // ���̾��
	IN PROCESSINFOCLASS InformationClass, // ��Ϣ����
	OUT PVOID ProcessInformation, // ����ָ��
	IN ULONG ProcessInformationLength, // ���ֽ�Ϊ��λ�Ļ����С
	OUT PULONG ReturnLength OPTIONAL // д�뻺����ֽ���
);
HANDLE HandleToPid(IN HANDLE ProcessID, IN HANDLE handle);