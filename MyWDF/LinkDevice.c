#include<ntifs.h>
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

