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
#include <QString>

#pragma execution_character_set("utf-8")


//宏定义错误处理
#define CHECK_ERROR(cond, msg) \
    if (!(cond)) { \
        QMessageBox::information(NULL, "ERROT", msg); \
		return; \
    }




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

static int text = 100;

///<summary>
///使用名称匹配，即可触发点击事件，槽函数=on_{UI名称}_clicked,UI名称必须是_Button后缀
///</summary>
void QtWidgetsApp::on_sync_Button_clicked() const {

	//获取
	QTextEdit* vauleEdit = findChild<QTextEdit*>("valueEdit");
	vauleEdit->setText(QString::number(text));

	//获取
	QTextEdit* addressEdit = findChild<QTextEdit*>("addressEdit");
	QString addressString = QString::asprintf("text的地址是 %p", static_cast<void*>(&text));
	addressEdit->setText(addressString);
}

///<summary>
///使用名称匹配，即可触发点击事件，槽函数=on_{UI名称}_clicked,UI名称必须是_Button后缀
///</summary>
void QtWidgetsApp::on_change_Button_clicked() const {

	//获取
	QTextEdit* newvauleEdit = findChild<QTextEdit*>("newvalueEdit");
	QString newtext = newvauleEdit->toPlainText();
	text = newtext.toInt();
}









