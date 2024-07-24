#include <ntddk.h>
#include "Driver.h"

#include "LinkDevice.h"
#include "���̱���.h" //�����Զ����ͷ�ļ� "���̱���.h"
#include "Զ�̶�д�ڴ�����.h" //�����Զ����ͷ�ļ� "���̱���.h"
#include "ͨ�������ַ��д�����ڴ�.h"
#include "��������ص�����.h"
#include "���������ӱ���.h"
#include "ͨ�������ȡ����.h"
#include "�������̵ľ��.h"


//r3���ú���
//WriteProcessMemoryд�ڴ�
//ReadProcessMemory ���ڴ�
//��������
//TerminateProcess
//VirtualProtectEx�޸�ҳ������
//VirtualAllocEx VirtualFreeEx
//CreateRemoteThread Ƭcal1
//DuplicateHandle ���Ʊ�

#define д���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define ������ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define ��д���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_����ܱ�����PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ɾ���ܱ�����PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_����ܱ�����PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_д���ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_��ȡ�ܱ����Ľ��� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define CTL_IO_�����ڴ�д�� CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����
#define CTL_IO_�����ڴ��ȡ CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //��д����

#define IO_�������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ɾ������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_�������Ȩ��PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

#define IO_ͨ�������ȡ���� CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������
#define IO_ͨ�����̱������ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //���������

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	//ж�ؽ��̱���
	ж�ؽ��̱���();
	//ж�ػص�����
	ObRegisterUnload();
	//ɾ����������
	DeleteDriver(DriverObject);
	KdPrint(("����ж��\n"));
}
NTSTATUS IRP_IO_д����(PIRP pirp) {
	/*char* ������ = pirp->AssociatedIrp.SystemBuffer;
	KdPrint(("������ǲ����IRP_MJ_DEVICE_CONTROL   ������Ϊ %X  ������: %s \n", д����, ������));*/
	UNREFERENCED_PARAMETER(pirp);
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_������(PIRP pirp) {
	char* ������ = pirp->AssociatedIrp.SystemBuffer;
	PIO_STACK_LOCATION irpStackL;
	irpStackL = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	//д�뻺����
	char �����ַ���[] = "123456";
	memcpy_s(������, sizeof(�����ַ���), �����ַ���, sizeof(�����ַ���));
	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = sizeof(�����ַ���);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_��д����(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	int* ������ = pirp->AssociatedIrp.SystemBuffer;
	if (������) {
		int* p = (int*)������;
		int ��� = p[0] + p[1] + p[2];
		*(int*)������ = ���;
		KdPrint(("�������Ϊ %d\n", ���));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_����ܱ�����PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	int* ������ = pirp->AssociatedIrp.SystemBuffer;
	if (������) {
		UINT64* pPID = (UINT64*)������;
		UINT64 pid = pPID[0];
		����ܱ�����PID(pid);
		KdPrint(("���� ����ܱ�����PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	}
	return STATUS_SUCCESS;
}

NTSTATUS IRP_IO_ɾ���ܱ�����PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	int* ������ = pirp->AssociatedIrp.SystemBuffer;
	if (������) {
		UINT64* pPID = (UINT64*)������;
		UINT64 pid = pPID[0];
		ɾ���ܱ�����PID(pid);
		KdPrint(("���� ɾ���ܱ�����PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_����ܱ�����PID(PIRP pirp) {
	pirp;
	����ܱ�������();
	return STATUS_SUCCESS;
}


NTSTATUS IRP_IO_�������Ȩ��PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	int* ������ = pirp->AssociatedIrp.SystemBuffer;
	if (������) {
		UINT64* pPID = (UINT64*)������;
		UINT64 pid = pPID[0];
		�������Ȩ��PID(pid);
		KdPrint(("���� �������Ȩ��PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_ɾ������Ȩ��PID(PIRP pirp) {
	PIO_STACK_LOCATION irpStack;
	irpStack = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���
	int* ������ = pirp->AssociatedIrp.SystemBuffer;
	if (������) {
		UINT64* pPID = (UINT64*)������;
		UINT64 pid = pPID[0];
		ɾ������Ȩ��PID(pid);
		KdPrint(("���� ɾ������Ȩ��PID %d\n", (int)pid));
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = sizeof(int);//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
		IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	}
	return STATUS_SUCCESS;
}
NTSTATUS IRP_IO_�������Ȩ��PID(PIRP pirp) {
	pirp;
	�������Ȩ����();
	return STATUS_SUCCESS;
}

NTSTATUS IRP_CALL(PDEVICE_OBJECT DriverObject, PIRP pirp) {

	UNREFERENCED_PARAMETER(DriverObject);//һ����Ч��
	KdPrint(("������ǲ��������\n"));
	PIO_STACK_LOCATION irpStackL;
	//ULONG CrlCode;
	//ULONG InputBuffLength;

	irpStackL = IoGetCurrentIrpStackLocation(pirp);//��ȡӦ�ò㴫���Ĳ���

	switch (irpStackL->MajorFunction) {

	case IRP_MJ_DEVICE_CONTROL:
	{
		if (irpStackL == NULL) {
			//�������
			return STATUS_INVALID_PARAMETER;
		}
		ULONG ������;
		������ = irpStackL->Parameters.DeviceIoControl.IoControlCode;
		switch (������) {
		case д����:
			return IRP_IO_д����(pirp);
		case ������:
			return IRP_IO_������(pirp);
		case ��д����:
			return IRP_IO_��д����(pirp);
		case IO_����ܱ�����PID:
			return IRP_IO_����ܱ�����PID(pirp);
		case IO_ɾ���ܱ�����PID:
			return IRP_IO_ɾ���ܱ�����PID(pirp);
		case IO_����ܱ�����PID:
			return IRP_IO_����ܱ�����PID(pirp);
		case IO_�������Ȩ��PID:
			return IRP_IO_����ܱ�����PID(pirp);
		case IO_ɾ������Ȩ��PID:
			return IRP_IO_ɾ������Ȩ��PID(pirp);
		case IO_�������Ȩ��PID:
			return IRP_IO_�������Ȩ��PID(pirp);
		case IO_д���ܱ����Ľ���:
			return IRP_WriteProcessMemory2(pirp);
		case IO_��ȡ�ܱ����Ľ���:
			return IRP_ReadProcessMemory2(pirp);;
		case CTL_IO_�����ڴ��ȡ:
			return IRP_ReadPVirtualMemory(pirp);
		case CTL_IO_�����ڴ�д��:
			return IRP_WritePVirtualMemory(pirp);
		case IO_ͨ�������ȡ����:
			return IRP_ͨ�������ȡ����(pirp);
		case IO_ͨ�����̱������:
			return IRP_ͨ�����̱������(pirp);
		}
	}
	case IRP_MJ_CREATE:
	{
		//��������������������
		EnumObRegisterCallBacks();
		KdPrint(("������ǲ����IRP_MJ_CREATE\n"));
	}
	case IRP_MJ_CLOSE:
	{
		KdPrint(("������ǲ����IRP_MJ_CLOSE\n"));
	}
	default:
		break;
	}

	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 4;//���ظ�DeviceIoContral�еĵ����ڶ�������IpBytesReturned
	IoCompleteRequest(pirp, IO_NO_INCREMENT);//���÷���������е�io����������������������ȼ�
	KdPrint(("������ǲ�����뿪"));
	return STATUS_SUCCESS;
}

//NTSTATUS IRP_WRITE(PDEVICE_OBJECT DriverObject, PIRP pirp) {
//	UNREFERENCED_PARAMETER(DriverObject);//һ����Ч��
//}
//NTSTATUS IRP_READ(PDEVICE_OBJECT DriverObject, PIRP pirp) {
//	UNREFERENCED_PARAMETER(DriverObject);//һ����Ч��
//}

typedef struct _KLDR_DATA__TABLE_ENTRY
{
	LIST_ENTRY listEntry;
	ULONG unknown1;
	ULONG unknown2;
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
	UNICODE_STRING path;
	UNICODE_STRING name;
	ULONG Flags;
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("������װ\n"));

	PKLDR_DATA_TABLE_ENTRY pobj = DriverObject->DriverSection;
	pobj->Flags |= 0x20;
	//����ж������
	DriverObject->DriverUnload = DriverUnload;

	//������ǲ����
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_CALL;

	//DriverObject->MajorFunction[IRP_MJ_WRITE] = IRP_WRITE; //��ӦR3��
	//DriverObject->MajorFunction[IRP_MJ_READ] = IRP_READ;
	//������������
	CreateDevice(DriverObject);

	//��ʼ���ص�
	ObRegisterCallBacksInit(DriverObject);

	//��װ���̱���
	��װ���̱���();

	return STATUS_SUCCESS;
}
