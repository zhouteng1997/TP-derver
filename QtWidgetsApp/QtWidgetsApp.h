#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApp.h"

class QtWidgetsApp : public QMainWindow
{
    Q_OBJECT

public:
    QtWidgetsApp(QWidget *parent = nullptr);
    ~QtWidgetsApp();

private:
    Ui::ui_QtWidgetsApp ui;

public slots:
    //�ۺ���

    //�������豸
    void on_open_Button_clicked();

    //�ر������豸
    void on_close_Button_clicked();

    //��д����
    void on_readdata_Button_clicked();

    //��д����
    void on_writedata_Button_clicked();

    //��д����
    void on_data_Button_clicked();

    //��������
    void on_load_Button_clicked();

    //ж������
    void on_unload_Button_clicked();

    //��ӽ��̱���
    void on_addPID_Button_clicked() const;

    //ɾ�����̱���
    void on_delPID_Button_clicked() const;

    //��ս��̱���
    void on_delAllPID_Button_clicked() const;

    //���̵�ַд��
    void on_addressWrite_Button_clicked() ;

    //���̵�ַ��ȡ
    void on_addressRead_Button_clicked();

    //�����ַд��
    void on_wladdressWrite_Button_clicked();

    //�����ַ��ȡ
    void on_wladdressRead_Button_clicked();

    //��ӽ��̱���
    void on_addQxPID_Button_clicked() const;

    //ɾ�����̱���
    void on_delQxPID_Button_clicked() const;

    //��ս��̱���
    void on_delAllQxPID_Button_clicked() const;

    //��ȡ�������
    void on_getHandle_Button_clicked();

    //����2000���
    void on_createHandle_Button_clicked();
};


