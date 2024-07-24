#include <ntifs.h>
#include "IO_ReadProcessMemory.h"



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

//���������豸����
#define ���������� L"\\??\\MyDriver"

//�����豸
NTSTATUS CreateDevice(PDRIVER_OBJECT driver)
{
	NTSTATUS status;
	UNICODE_STRING MyDriver;
	PDEVICE_OBJECT device;//���ڴ���豸����
	RtlInitUnicodeString(&MyDriver, L"\\DEVICE\\MyDriver");//�����豸����
	status = IoCreateDevice(driver,
		sizeof(driver->DriverExtension),
		&MyDriver,
		FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);

	if (status == STATUS_SUCCESS)//STATUS_SUCCESS)
	{
		KdPrint(("�����豸���󴴽��ɹ�,OK \n"));//������������
		UNICODE_STRING uzSymbolName; //������������
		RtlInitUnicodeString(&uzSymbolName, ����������); //CreateFile
		status = IoCreateSymbolicLink(&uzSymbolName, &MyDriver);
		if (status == STATUS_SUCCESS)
		{
			KdPrint(("���������������� %wZ �ɹ�", &uzSymbolName));
		}
		else {
			KdPrint(("���������������� %wZ ʧ�� status=%X", &uzSymbolName, status));
		}
	}
	else {
		KdPrint(("�����豸���󴴽�ʧ�ܣ�ɾ���豸"));
		if (device == NULL)	//�޸������жϽ�����־���Warning C6387
			return status;	//���if������������return �����Ч����0���ظ�������������ǰ�����˳���
		IoDeleteDevice(device);
	}
	return status;
}

//ɾ���豸
void DeleteDriver(PDRIVER_OBJECT pDriver)
{
	KdPrint(("����������ж������"));
	if (pDriver->DeviceObject)
	{

		//ɾ����������
		UNICODE_STRING uzSymbolName;//������������
		RtlInitUnicodeString(&uzSymbolName, ����������); //CreateFile
		KdPrint(("����ɾ����������=%wZ", &uzSymbolName));
		IoDeleteSymbolicLink(&uzSymbolName);
		//
		KdPrint(("����ɾ�������豸"));
		IoDeleteDevice(pDriver->DeviceObject);//ɾ���豸����
	}
	KdPrint(("�����˳�ж������"));
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	//ɾ����������
	DeleteDriver(DriverObject);
	KdPrint(("����ж��\n"));
}

NTSTATUS IRP_CALL(PDEVICE_OBJECT DriverObject, PIRP pirp) {

	UNREFERENCED_PARAMETER(DriverObject);//һ����Ч��
	KdPrint(("������ǲ��������\n"));
	PIO_STACK_LOCATION irpStackL;
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
		case IO_��ȡ�ܱ����Ľ���:
			return IRP_ReadProcessMemory(pirp);
		//case IO_д���ܱ����Ľ���:
		//	return IRP_WriteProcessMemory2(pirp);
		//case CTL_IO_�����ڴ��ȡ:
		//	return IRP_ReadPVirtualMemory(pirp);
		//case CTL_IO_�����ڴ�д��:
		//	return IRP_WritePVirtualMemory(pirp);
		//case IO_ͨ�������ȡ����:
		//	return IRP_ͨ�������ȡ����(pirp);
		//case IO_ͨ�����̱������:
		//	return IRP_ͨ�����̱������(pirp);
		}
	}
	case IRP_MJ_CREATE:
	{
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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("������װ\n"));
	//����ж������
	DriverObject->DriverUnload = DriverUnload;
	//������ǲ����
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_CALL;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IRP_CALL;
	//������������
	CreateDevice(DriverObject);
	return STATUS_SUCCESS;
}
