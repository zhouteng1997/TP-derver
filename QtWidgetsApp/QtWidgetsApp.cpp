//�������  windeployqt

#include "QtWidgetsApp.h"
#include "ui_QtWidgetsApp.h"
#include <qdebug.h>
#include <QMessageBox>
#include <QTextEdit>
#include <QThread>
#include<windows.h>
#include <winioctl.h>
#include <string> //����std::wstring
#include <stdint.h>  //for uintptr_t
#include <TlHelp32.h> 
#include <comdef.h>

#pragma execution_character_set("utf-8")


//�궨�������
#define CHECK_ERROR(cond, msg) \
    if (!(cond)) { \
        QMessageBox::information(NULL, "ERROT", msg); \
		return; \
    }


static HANDLE DeviceHandle = NULL;
#define ���������� L"\\??\\MyDriver"
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


QtWidgetsApp::QtWidgetsApp(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	//���û��ʹ������ƥ�䣬����ʹ��connect����UI���������ĵ���¼�
	//connect(ui.open_Button, SIGNAL(clicked()), this, SLOT(on_open_Button_clicked()));

	//�����ĵ���¼�
	//connect(ui.open_Button, &QPushButton::clicked, this, [=]() {
	//	qDebug() << "1997";
	//	});
}

QtWidgetsApp::~QtWidgetsApp()
{

}

///<summary>
///ʹ������ƥ�䣬���ɴ�������¼����ۺ���=on_{UI����}_clicked,UI���Ʊ�����_Button��׺
///</summary>
//���豸
void QtWidgetsApp::on_open_Button_clicked() {
	//�ڴ���ӿؼ�֪ͨ����������
	DeviceHandle = CreateFileW(
		����������,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	QString handleStr = "���� R3 �豸���:" + QString::number(reinterpret_cast<quintptr>(DeviceHandle), 16);
	QMessageBox::information(NULL, "Information", "���� R3 �豸���:" + handleStr);
	return;
}

///<summary>
///ʹ������ƥ�䣬���ɴ�������¼����ۺ���=on_{UI����}_clicked
///</summary>
//�ر��豸
void QtWidgetsApp::on_close_Button_clicked() {
	//�ر��豸
	if (DeviceHandle != NULL)
		CloseHandle(DeviceHandle);
}

//д����
void QtWidgetsApp::on_writedata_Button_clicked() {
	//���������Ŀ�����
	char buffer[256];
	sprintf_s(buffer, "%X \n", д����);
	QString str = buffer;//��c[0]�ĵ�ַ����str
	QMessageBox::information(NULL, "Information", " ���� R3 ��������ַ:" + str);

	//����豸
	QString handleStr = QString::number(reinterpret_cast<quintptr>(DeviceHandle), 16);
	QMessageBox::information(NULL, "Information", "���� R3 �豸���:" + handleStr);

	DWORD dwRetSize = 0;//�����ֽ���
	char ��������[] = "���� R3 д���� \n";
	DWORD OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		д����,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QMessageBox::information(NULL, "Information", "���� R3 �����ֽ�:" + handleStr);
}

//������
void QtWidgetsApp::on_readdata_Button_clicked() {
	DWORD dwRetSize = 0;//�����ֽ���
	char ��������[] = "";
	//д�뻺����
	char OutBuf[512] = "";//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		������,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = OutBuf;
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
}

//��д����
void QtWidgetsApp::on_data_Button_clicked() {
	DWORD dwRetSize = 0;//�����ֽ���
	int ��������[3] = { 1,2,3 };
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		��д����,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
}

//��������
void QtWidgetsApp::on_load_Button_clicked() {
	//��ȡ��������С ��ǰĿ¼
	wchar_t cwd[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, cwd);
	//������ַ
	std::wstring str1 = cwd;
	std::wstring str2 = L"MyWDF.sys";
	std::wstring Path = str1 + L"\\" + str2;
	LPCWSTR driverPath = Path.c_str();
	//QMessageBox::information(NULL, "information", QString::fromWCharArray(driverPath));
	//��������
	LPCWSTR driverName = L"MyWDF";
	//��������
	SC_HANDLE hServiceMgr = NULL;//SCM�������ľ��
	SC_HANDLE hServiceDDK = NULL;//NT��������ķ�����
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);//��SCM������
	//CHECK_ERROR(hServiceMgr != NULL, "OpenSCManager failed");
	hServiceDDK = CreateService(
		hServiceMgr,
		driverName,//����������ע��������
		driverName,//ע������������displayֵ
		SERVICE_START | DELETE | SERVICE_STOP,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		driverPath,//ע������������·��
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	DWORD error = GetLastError();
	//���������Ŀ�����
	//char buffer[256];
	//sprintf_s(buffer, "���� �������� hServiceDDK=%X ,GetLastError= %d \n", (uintptr_t)hServiceMgr, (int)GetLastError());
	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "���� �������� hServiceDDK=%llu ,GetLastError= %d \n", (UINT64)hServiceMgr, error);
	QString str = buffer;//��c[0]�ĵ�ַ����str
	//QMessageBox::information(NULL, "Information", str);


	if (!hServiceDDK) {
		sprintf_s(buffer, sizeof(buffer), "���� �������� error=%d \n", error);
		QString str = buffer;//��c[0]�ĵ�ַ����str
		QMessageBox::information(NULL, "Information", str);
		if (error == ERROR_SERVICE_EXISTS) {
			hServiceDDK = OpenService(hServiceMgr, driverName, SERVICE_START | DELETE | SERVICE_STOP);
			CHECK_ERROR(hServiceDDK != NULL, "�򿪷��� ʧ��");
		}
		else {
			QMessageBox::information(NULL, "ERROR", "CreateService failed");
			CloseServiceHandle(hServiceMgr);
			return;
		}
	}

	if (hServiceDDK) {
		CHECK_ERROR(StartService(hServiceDDK, 0, NULL), "StartService failed");
	}
	QMessageBox::information(NULL, "Information", "Driver loaded success");
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return;
}

//ж������
void QtWidgetsApp::on_unload_Button_clicked()
{
	//��������
	LPCWSTR driverName = L"MyWDF";
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	CHECK_ERROR(schSCManager != NULL, "OpenSCManager failed");

	SC_HANDLE schService = OpenService(schSCManager, driverName, SERVICE_STOP | DELETE);
	CHECK_ERROR(schService != NULL, "OpenService failed");

	SERVICE_STATUS ss;
	CHECK_ERROR(ControlService(schService, SERVICE_CONTROL_STOP, &ss), "ControlService failed");

	//�ȴ�һ��ʱ��ȷ��������ȫֹͣ
	QThread::msleep(5000);  //��ͣ5000���룬��5��

	CHECK_ERROR(DeleteService(schService), "DeleteService failed");

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	return;
}

//��ӱ���PID
void QtWidgetsApp::on_addPID_Button_clicked() const {
	//��ȡ
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = number;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_����ܱ�����PID,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//ɾ������PID
void QtWidgetsApp::on_delPID_Button_clicked() const {
	//��ȡ
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = number;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_ɾ���ܱ�����PID,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//��ձ���PID
void QtWidgetsApp::on_delAllPID_Button_clicked() const {
	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = 1;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_����ܱ�����PID,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//ȥ����д����
void QtWidgetsApp::on_addressWrite_Button_clicked()
{
	//��ȡ
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//��ȡ
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//��ȡ
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();


#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//Ŀ�����
		PVOID pBase;///Ŀ����̵�ַ
		UINT32 nSize;//Ҫ��ȡ�ĳ���
		PVOID pbuf;//Ҫд�����ݵĵ�ַ
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF ��������;
	��������.dwPid = pid2.toInt(); //Ŀ�����ID
	bool ok;
	��������.pBase = (PVOID)address2.toULongLong(&ok, 16); //Ŀ����̵�ַ



	int aaa = content2.toInt();
	��������.nSize = sizeof(aaa);
	��������.pbuf = (PVOID)&aaa; //Ҫд������ݵĵ�ַ

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p pbuf = %p \n", ��������.pBase, ��������.pbuf);
	QString str1 = buffer;//��c[0]�ĵ�ַ����str
	QMessageBox::information(NULL, "Information", str1);


	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DWORD dwRetSize = 0;//�����ֽ���

	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_д���ܱ����Ľ���,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);
	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//ȥ���̶�����
void QtWidgetsApp::on_addressRead_Button_clicked() {
	//��ȡ
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//��ȡ
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//��ȡ
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();


#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//Ŀ�����
		PVOID pBase;///Ŀ����̵�ַ
		UINT32 nSize;//Ҫ��ȡ�ĳ���
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF ��������;
	��������.dwPid = pid2.toInt(); //Ŀ�����ID
	bool ok;
	��������.pBase = (PVOID)address2.toULongLong(&ok, 16); //Ŀ����̵�ַ

	int aaa = content2.toInt();
	��������.nSize = sizeof(aaa);

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p  \n", ��������.pBase);
	QString str1 = buffer;//��c[0]�ĵ�ַ����str
	QMessageBox::information(NULL, "Information", str1);


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
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	content2Edit->setText(str);
	return;
}

//�ѽ��̵�ַӳ�䵽�����ַ��д����
void QtWidgetsApp::on_wladdressWrite_Button_clicked()
{
	//��ȡ
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//��ȡ
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//��ȡ
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();

#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//Ŀ�����
		PVOID pBase;///Ŀ����̵�ַ
		UINT32 nSize;//Ҫ��ȡ�ĳ���
		PVOID pbuf;//Ҫд�����ݵĵ�ַ
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF ��������;
	��������.dwPid = pid2.toInt(); //Ŀ�����ID
	bool ok;
	��������.pBase = (PVOID)address2.toULongLong(&ok, 16); //Ŀ����̵�ַ



	int aaa = content2.toInt();
	��������.nSize = sizeof(aaa);
	��������.pbuf = (PVOID)&aaa; //Ҫд������ݵĵ�ַ

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p pbuf = %p \n", ��������.pBase, ��������.pbuf);
	QString str1 = buffer;//��c[0]�ĵ�ַ����str
	QMessageBox::information(NULL, "Information", str1);


	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DWORD dwRetSize = 0;//�����ֽ���

	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		CTL_IO_�����ڴ�д��,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);
	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//�ѽ��̵�ַӳ�䵽�����ַ��������
void QtWidgetsApp::on_wladdressRead_Button_clicked() {
	//��ȡ
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//��ȡ
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//��ȡ
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();


#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//Ŀ�����
		PVOID pBase;///Ŀ����̵�ַ
		UINT32 nSize;//Ҫ��ȡ�ĳ���
		PVOID pbuf;//Ҫд�����ݵĵ�ַ
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF ��������;
	��������.dwPid = pid2.toInt(); //Ŀ�����ID
	bool ok;
	��������.pBase = (PVOID)address2.toULongLong(&ok, 16); //Ŀ����̵�ַ



	int aaa = content2.toInt();
	��������.nSize = sizeof(aaa);
	��������.pbuf = (PVOID)&aaa; //Ҫд������ݵĵ�ַ

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p pbuf = %p \n", ��������.pBase, ��������.pbuf);
	QString str1 = buffer;//��c[0]�ĵ�ַ����str
	QMessageBox::information(NULL, "Information", str1);


	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DWORD dwRetSize = 0;//�����ֽ���

	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		CTL_IO_�����ڴ��ȡ,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);
	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	content2Edit->setText(str);
	return;
}

//���Ȩ��PID
void QtWidgetsApp::on_addQxPID_Button_clicked() const {
	//��ȡ
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = number;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_�������Ȩ��PID,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//ɾ��Ȩ��PID
void QtWidgetsApp::on_delQxPID_Button_clicked() const {
	//��ȡ
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = number;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_ɾ������Ȩ��PID,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

//���Ȩ��PID
void QtWidgetsApp::on_delAllQxPID_Button_clicked() const {
	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = 1;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_�������Ȩ��PID,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}

HANDLE ���̾��1 = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
HANDLE ���̾��2 = OpenProcess(PROCESS_SET_LIMITED_INFORMATION, false, GetCurrentProcessId());

DWORD pid = GetCurrentProcessId();



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
		_bstr_t processName(processer.szExeFile);  //WCHAR�ַ���ת����CHAR�ַ���
		if (strcmp(processName, name) == 0)
		{
			return processer.th32ProcessID;        //���ؽ���ID
		}
		flag = Process32Next(hsnapshot, &processer);
	}

	CloseHandle(hsnapshot);
	return 0;
}
HANDLE ���̾��2000 = NULL;
void ����2000���()
{
	char buf[256];
	//HWND h = FindWindowA("Windows.UI.Core.CoreWindow", "������");
	DWORD pid = (DWORD)GetProcessIdFromName("CalculatorApp.exe");
	if (pid == 0)
	{
		pid = (DWORD)GetProcessIdFromName("win32calc.exe");
		if (pid == 0)
		{
			QMessageBox::information(NULL, "Information", "��Ҫ�ȴ�->������");
			return;
		}
	}
	//DWORD pid = 0;
	//GetWindowThreadProcessId(h, &pid);
	for (int i = 0; i < 0x2000; i++)
	{
		���̾��2000 = OpenProcess(0x23456, false, pid);
		//sprintf_s(buf, "����:exe pid= %d  i = %03X  ���̾�� = %p \n", pid, i, ���̾��2000);
		//OutputDebugStringA(buf);
	}
	sprintf_s(buf, "yjx:exe pid= %d ���̾��2000 = %p \n", pid, ���̾��2000);
	QMessageBox::information(NULL, "Information", buf);
}
//CD0078MFCDIg��Ϣ�������


	//����2000���
void  QtWidgetsApp::on_createHandle_Button_clicked() {
	����2000���();
}

HANDLE ���̾��[0x20000];
void ��ȡ�������(HANDLE ���) {
	DWORD dwRetSize = 0;//�����ֽ���
	HANDLE �������� = ���;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������

	QString str = QString::number((ULONG64)���);
	QMessageBox::information(NULL, "Information", "���Ϊ:" + str);
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_ͨ�������ȡ����,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);

	//����豸

	return;
}
//��ȡ�������
void  QtWidgetsApp::on_getHandle_Button_clicked() {

	//��ȡ
	//QTextEdit* textEdit = findChild<QTextEdit*>("HandleEdit");
	//QString text = textEdit->toPlainText();
	//uint64_t number = text.toULongLong();
	//��ȡ�������(���̾��2);
	//for (int i = 0; i < 0x20000; i++) {
	���̾��[0] = OpenProcess(0x2826, false, GetCurrentProcessId());
	//}
	��ȡ�������(���̾��[0]);
	return;
}


//�������̾��
void  QtWidgetsApp::on_emunHandlePID_Button_clicked() {
	//��ȡ
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();
	uint64_t number = pid2.toULongLong();

	DWORD dwRetSize = 0;//�����ֽ���
	uint64_t �������� = number;
	//д�뻺����
	int OutBuf[1] = { 0 };//���������
	DeviceIoControl(
		DeviceHandle,//CreateFile�������豸���صľ��
		IO_ͨ�����̱������,//������CTL_CODE

		&��������,//���뻺����ָ��
		sizeof(��������),//���뻺������С

		&OutBuf,//���ػ�����
		sizeof(OutBuf),//���ػ�������С

		&dwRetSize,//�����ֽ���
		NULL);
	//����豸
	//QString str = QString::number(OutBuf[0]);
	//QMessageBox::information(NULL, "Information", "���� R0 ���ظ� R3 ������Ϊ:" + str);
	return;
}










