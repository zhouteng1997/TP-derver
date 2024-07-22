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
    //槽函数

    //打开驱动设备
    void on_open_Button_clicked();

    //关闭驱动设备
    void on_close_Button_clicked();

    //读写数据
    void on_readdata_Button_clicked();

    //读写数据
    void on_writedata_Button_clicked();

    //读写数据
    void on_data_Button_clicked();

    //加载驱动
    void on_load_Button_clicked();

    //卸载驱动
    void on_unload_Button_clicked();

    //添加进程保护
    void on_addPID_Button_clicked() const;

    //删除进程保护
    void on_delPID_Button_clicked() const;

    //清空进程保护
    void on_delAllPID_Button_clicked() const;

    //进程地址写入
    void on_addressWrite_Button_clicked() ;

    //进程地址读取
    void on_addressRead_Button_clicked();

    //物理地址写入
    void on_wladdressWrite_Button_clicked();

    //物理地址读取
    void on_wladdressRead_Button_clicked();

    //添加进程保护
    void on_addQxPID_Button_clicked() const;

    //删除进程保护
    void on_delQxPID_Button_clicked() const;

    //清空进程保护
    void on_delAllQxPID_Button_clicked() const;

    //获取句柄对象
    void on_getHandle_Button_clicked();

    //创建2000句柄
    void on_createHandle_Button_clicked();
};


