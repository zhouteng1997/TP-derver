//打包命令  windeployqt

#include "QtWidgetsApp.h"
#include "ui_QtWidgetsApp.h"
#include <qdebug.h>
#include <QMessageBox>
#include <QTextEdit>
#include <QThread>
#include<windows.h>
#include <winioctl.h>
#include <string> //包含std::wstring
#include <stdint.h>  //for uintptr_t
#include <TlHelp32.h> 
#include <comdef.h>

#pragma execution_character_set("utf-8")


//宏定义错误处理
#define CHECK_ERROR(cond, msg) \
    if (!(cond)) { \
        QMessageBox::information(NULL, "ERROT", msg); \
		return; \
    }


static HANDLE DeviceHandle = NULL;
#define 符号链接名 L"\\??\\MyDriver"
#define 写测试 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define 读测试 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define 读写测试 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_添加受保护的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_删除受保护的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_清空受保护的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_写入受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_读取受保护的进程 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define CTL_IO_物理内存写入 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80c,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试
#define CTL_IO_物理内存读取 CTL_CODE(FILE_DEVICE_UNKNOWN,0x80d,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写测试

#define IO_添加需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_删除需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_清空需提权的PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

#define IO_通过句柄获取对象 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试
#define IO_通过进程遍历句柄 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试


QtWidgetsApp::QtWidgetsApp(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	//如果没有使用名称匹配，可以使用connect连接UI名称与它的点击事件
	//connect(ui.open_Button, SIGNAL(clicked()), this, SLOT(on_open_Button_clicked()));

	//匿名的点击事件
	//connect(ui.open_Button, &QPushButton::clicked, this, [=]() {
	//	qDebug() << "1997";
	//	});
}

QtWidgetsApp::~QtWidgetsApp()
{

}

///<summary>
///使用名称匹配，即可触发点击事件，槽函数=on_{UI名称}_clicked,UI名称必须是_Button后缀
///</summary>
//打开设备
void QtWidgetsApp::on_open_Button_clicked() {
	//在此添加控件通知处理程序代码
	DeviceHandle = CreateFileW(
		符号链接名,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	QString handleStr = "驱动 R3 设备句柄:" + QString::number(reinterpret_cast<quintptr>(DeviceHandle), 16);
	QMessageBox::information(NULL, "Information", "驱动 R3 设备句柄:" + handleStr);
	return;
}

///<summary>
///使用名称匹配，即可触发点击事件，槽函数=on_{UI名称}_clicked
///</summary>
//关闭设备
void QtWidgetsApp::on_close_Button_clicked() {
	//关闭设备
	if (DeviceHandle != NULL)
		CloseHandle(DeviceHandle);
}

//写测试
void QtWidgetsApp::on_writedata_Button_clicked() {
	//输出测试码的控制码
	char buffer[256];
	sprintf_s(buffer, "%X \n", 写测试);
	QString str = buffer;//将c[0]的地址赋给str
	QMessageBox::information(NULL, "Information", " 驱动 R3 读驱动地址:" + str);

	//输出设备
	QString handleStr = QString::number(reinterpret_cast<quintptr>(DeviceHandle), 16);
	QMessageBox::information(NULL, "Information", "驱动 R3 设备句柄:" + handleStr);

	DWORD dwRetSize = 0;//返回字节数
	char 传入数据[] = "驱动 R3 写测试 \n";
	DWORD OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		写测试,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QMessageBox::information(NULL, "Information", "驱动 R3 返回字节:" + handleStr);
}

//读测试
void QtWidgetsApp::on_readdata_Button_clicked() {
	DWORD dwRetSize = 0;//返回字节数
	char 传入数据[] = "";
	//写入缓冲区
	char OutBuf[512] = "";//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		读测试,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = OutBuf;
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
}

//读写测试
void QtWidgetsApp::on_data_Button_clicked() {
	DWORD dwRetSize = 0;//返回字节数
	int 传入数据[3] = { 1,2,3 };
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		读写测试,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
}

//加载驱动
void QtWidgetsApp::on_load_Button_clicked() {
	//获取缓冲区大小 当前目录
	wchar_t cwd[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, cwd);
	//驱动地址
	std::wstring str1 = cwd;
	std::wstring str2 = L"MyWDF.sys";
	std::wstring Path = str1 + L"\\" + str2;
	LPCWSTR driverPath = Path.c_str();
	//QMessageBox::information(NULL, "information", QString::fromWCharArray(driverPath));
	//驱动名称
	LPCWSTR driverName = L"MyWDF";
	//加载驱动
	SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);//打开SCM管理器
	//CHECK_ERROR(hServiceMgr != NULL, "OpenSCManager failed");
	hServiceDDK = CreateService(
		hServiceMgr,
		driverName,//驱动程序在注册表的名称
		driverName,//注册表驱动程序的display值
		SERVICE_START | DELETE | SERVICE_STOP,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		driverPath,//注册表驱动程序的路径
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	DWORD error = GetLastError();
	//输出测试码的控制码
	//char buffer[256];
	//sprintf_s(buffer, "驱动 创建服务 hServiceDDK=%X ,GetLastError= %d \n", (uintptr_t)hServiceMgr, (int)GetLastError());
	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "驱动 创建服务 hServiceDDK=%llu ,GetLastError= %d \n", (UINT64)hServiceMgr, error);
	QString str = buffer;//将c[0]的地址赋给str
	//QMessageBox::information(NULL, "Information", str);


	if (!hServiceDDK) {
		sprintf_s(buffer, sizeof(buffer), "驱动 创建服务 error=%d \n", error);
		QString str = buffer;//将c[0]的地址赋给str
		QMessageBox::information(NULL, "Information", str);
		if (error == ERROR_SERVICE_EXISTS) {
			hServiceDDK = OpenService(hServiceMgr, driverName, SERVICE_START | DELETE | SERVICE_STOP);
			CHECK_ERROR(hServiceDDK != NULL, "打开服务 失败");
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

//卸载驱动
void QtWidgetsApp::on_unload_Button_clicked()
{
	//驱动名称
	LPCWSTR driverName = L"MyWDF";
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	CHECK_ERROR(schSCManager != NULL, "OpenSCManager failed");

	SC_HANDLE schService = OpenService(schSCManager, driverName, SERVICE_STOP | DELETE);
	CHECK_ERROR(schService != NULL, "OpenService failed");

	SERVICE_STATUS ss;
	CHECK_ERROR(ControlService(schService, SERVICE_CONTROL_STOP, &ss), "ControlService failed");

	//等待一段时间确保服务完全停止
	QThread::msleep(5000);  //暂停5000毫秒，即5秒

	CHECK_ERROR(DeleteService(schService), "DeleteService failed");

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	return;
}

//添加保护PID
void QtWidgetsApp::on_addPID_Button_clicked() const {
	//获取
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = number;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_添加受保护的PID,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//删除保护PID
void QtWidgetsApp::on_delPID_Button_clicked() const {
	//获取
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = number;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_删除受保护的PID,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//清空保护PID
void QtWidgetsApp::on_delAllPID_Button_clicked() const {
	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = 1;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_清空受保护的PID,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//去进程写数据
void QtWidgetsApp::on_addressWrite_Button_clicked()
{
	//获取
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//获取
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//获取
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();


#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//目标进程
		PVOID pBase;///目标进程地址
		UINT32 nSize;//要读取的长度
		PVOID pbuf;//要写入数据的地址
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF 传入数据;
	传入数据.dwPid = pid2.toInt(); //目标进程ID
	bool ok;
	传入数据.pBase = (PVOID)address2.toULongLong(&ok, 16); //目标进程地址



	int aaa = content2.toInt();
	传入数据.nSize = sizeof(aaa);
	传入数据.pbuf = (PVOID)&aaa; //要写入的数据的地址

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p pbuf = %p \n", 传入数据.pBase, 传入数据.pbuf);
	QString str1 = buffer;//将c[0]的地址赋给str
	QMessageBox::information(NULL, "Information", str1);


	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DWORD dwRetSize = 0;//返回字节数

	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_写入受保护的进程,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);
	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//去进程读数据
void QtWidgetsApp::on_addressRead_Button_clicked() {
	//获取
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//获取
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//获取
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();


#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//目标进程
		PVOID pBase;///目标进程地址
		UINT32 nSize;//要读取的长度
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF 传入数据;
	传入数据.dwPid = pid2.toInt(); //目标进程ID
	bool ok;
	传入数据.pBase = (PVOID)address2.toULongLong(&ok, 16); //目标进程地址

	int aaa = content2.toInt();
	传入数据.nSize = sizeof(aaa);

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p  \n", 传入数据.pBase);
	QString str1 = buffer;//将c[0]的地址赋给str
	QMessageBox::information(NULL, "Information", str1);


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
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	content2Edit->setText(str);
	return;
}

//把进程地址映射到物理地址，写数据
void QtWidgetsApp::on_wladdressWrite_Button_clicked()
{
	//获取
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//获取
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//获取
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();

#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//目标进程
		PVOID pBase;///目标进程地址
		UINT32 nSize;//要读取的长度
		PVOID pbuf;//要写入数据的地址
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF 传入数据;
	传入数据.dwPid = pid2.toInt(); //目标进程ID
	bool ok;
	传入数据.pBase = (PVOID)address2.toULongLong(&ok, 16); //目标进程地址



	int aaa = content2.toInt();
	传入数据.nSize = sizeof(aaa);
	传入数据.pbuf = (PVOID)&aaa; //要写入的数据的地址

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p pbuf = %p \n", 传入数据.pBase, 传入数据.pbuf);
	QString str1 = buffer;//将c[0]的地址赋给str
	QMessageBox::information(NULL, "Information", str1);


	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DWORD dwRetSize = 0;//返回字节数

	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		CTL_IO_物理内存写入,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);
	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//把进程地址映射到物理地址，读数据
void QtWidgetsApp::on_wladdressRead_Button_clicked() {
	//获取
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();

	//获取
	QTextEdit* address2Edit = findChild<QTextEdit*>("address2Edit");
	QString address2 = address2Edit->toPlainText();

	//获取
	QTextEdit* content2Edit = findChild<QTextEdit*>("content2Edit");
	QString content2 = content2Edit->toPlainText();


#pragma pack (push)
#pragma pack(8)
	typedef struct TINPUT_BUF
	{
		UINT32 dwPid;//目标进程
		PVOID pBase;///目标进程地址
		UINT32 nSize;//要读取的长度
		PVOID pbuf;//要写入数据的地址
	}TINPUT_BUF;
#pragma pack (pop)
	TINPUT_BUF 传入数据;
	传入数据.dwPid = pid2.toInt(); //目标进程ID
	bool ok;
	传入数据.pBase = (PVOID)address2.toULongLong(&ok, 16); //目标进程地址



	int aaa = content2.toInt();
	传入数据.nSize = sizeof(aaa);
	传入数据.pbuf = (PVOID)&aaa; //要写入的数据的地址

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "pBase = %p pbuf = %p \n", 传入数据.pBase, 传入数据.pbuf);
	QString str1 = buffer;//将c[0]的地址赋给str
	QMessageBox::information(NULL, "Information", str1);


	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DWORD dwRetSize = 0;//返回字节数

	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		CTL_IO_物理内存读取,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);
	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	content2Edit->setText(str);
	return;
}

//添加权限PID
void QtWidgetsApp::on_addQxPID_Button_clicked() const {
	//获取
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = number;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_添加需提权的PID,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//删除权限PID
void QtWidgetsApp::on_delQxPID_Button_clicked() const {
	//获取
	QTextEdit* textEdit = findChild<QTextEdit*>("PIDEdit");
	QString text = textEdit->toPlainText();
	uint64_t number = text.toULongLong();

	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = number;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_删除需提权的PID,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

//清空权限PID
void QtWidgetsApp::on_delAllQxPID_Button_clicked() const {
	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = 1;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_清空需提权的PID,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备
	QString str = QString::number(OutBuf[0]);
	QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}

HANDLE 进程句柄1 = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
HANDLE 进程句柄2 = OpenProcess(PROCESS_SET_LIMITED_INFORMATION, false, GetCurrentProcessId());

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
		_bstr_t processName(processer.szExeFile);  //WCHAR字符串转换成CHAR字符串
		if (strcmp(processName, name) == 0)
		{
			return processer.th32ProcessID;        //返回进程ID
		}
		flag = Process32Next(hsnapshot, &processer);
	}

	CloseHandle(hsnapshot);
	return 0;
}
HANDLE 进程句柄2000 = NULL;
void 创建2000句柄()
{
	char buf[256];
	//HWND h = FindWindowA("Windows.UI.Core.CoreWindow", "计算器");
	DWORD pid = (DWORD)GetProcessIdFromName("CalculatorApp.exe");
	if (pid == 0)
	{
		pid = (DWORD)GetProcessIdFromName("win32calc.exe");
		if (pid == 0)
		{
			QMessageBox::information(NULL, "Information", "需要先打开->计算器");
			return;
		}
	}
	//DWORD pid = 0;
	//GetWindowThreadProcessId(h, &pid);
	for (int i = 0; i < 0x2000; i++)
	{
		进程句柄2000 = OpenProcess(0x23456, false, pid);
		//sprintf_s(buf, "驱动:exe pid= %d  i = %03X  进程句柄 = %p \n", pid, i, 进程句柄2000);
		//OutputDebugStringA(buf);
	}
	sprintf_s(buf, "yjx:exe pid= %d 进程句柄2000 = %p \n", pid, 进程句柄2000);
	QMessageBox::information(NULL, "Information", buf);
}
//CD0078MFCDIg消息处理程序


	//创建2000句柄
void  QtWidgetsApp::on_createHandle_Button_clicked() {
	创建2000句柄();
}

HANDLE 进程句柄[0x20000];
void 获取句柄对象(HANDLE 句柄) {
	DWORD dwRetSize = 0;//返回字节数
	HANDLE 传入数据 = 句柄;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区

	QString str = QString::number((ULONG64)句柄);
	QMessageBox::information(NULL, "Information", "句柄为:" + str);
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_通过句柄获取对象,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);

	//输出设备

	return;
}
//获取句柄对象
void  QtWidgetsApp::on_getHandle_Button_clicked() {

	//获取
	//QTextEdit* textEdit = findChild<QTextEdit*>("HandleEdit");
	//QString text = textEdit->toPlainText();
	//uint64_t number = text.toULongLong();
	//获取句柄对象(进程句柄2);
	//for (int i = 0; i < 0x20000; i++) {
	进程句柄[0] = OpenProcess(0x2826, false, GetCurrentProcessId());
	//}
	获取句柄对象(进程句柄[0]);
	return;
}


//遍历进程句柄
void  QtWidgetsApp::on_emunHandlePID_Button_clicked() {
	//获取
	QTextEdit* PID2Edit = findChild<QTextEdit*>("PID2Edit");
	QString pid2 = PID2Edit->toPlainText();
	uint64_t number = pid2.toULongLong();

	DWORD dwRetSize = 0;//返回字节数
	uint64_t 传入数据 = number;
	//写入缓冲区
	int OutBuf[1] = { 0 };//输出缓冲区
	DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		IO_通过进程遍历句柄,//控制码CTL_CODE

		&传入数据,//输入缓冲区指针
		sizeof(传入数据),//输入缓冲区大小

		&OutBuf,//返回缓冲区
		sizeof(OutBuf),//返回缓冲区大小

		&dwRetSize,//返回字节数
		NULL);
	//输出设备
	//QString str = QString::number(OutBuf[0]);
	//QMessageBox::information(NULL, "Information", "驱动 R0 返回给 R3 的数据为:" + str);
	return;
}










