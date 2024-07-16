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
#include <QString>

#pragma execution_character_set("utf-8")


//�궨�������
#define CHECK_ERROR(cond, msg) \
    if (!(cond)) { \
        QMessageBox::information(NULL, "ERROT", msg); \
		return; \
    }




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

static int text = 100;

///<summary>
///ʹ������ƥ�䣬���ɴ�������¼����ۺ���=on_{UI����}_clicked,UI���Ʊ�����_Button��׺
///</summary>
void QtWidgetsApp::on_sync_Button_clicked() const {

	//��ȡ
	QTextEdit* vauleEdit = findChild<QTextEdit*>("valueEdit");
	vauleEdit->setText(QString::number(text));

	//��ȡ
	QTextEdit* addressEdit = findChild<QTextEdit*>("addressEdit");
	QString addressString = QString::asprintf("text�ĵ�ַ�� %p", static_cast<void*>(&text));
	addressEdit->setText(addressString);
}

///<summary>
///ʹ������ƥ�䣬���ɴ�������¼����ۺ���=on_{UI����}_clicked,UI���Ʊ�����_Button��׺
///</summary>
void QtWidgetsApp::on_change_Button_clicked() const {

	//��ȡ
	QTextEdit* newvauleEdit = findChild<QTextEdit*>("newvalueEdit");
	QString newtext = newvauleEdit->toPlainText();
	text = newtext.toInt();
}









