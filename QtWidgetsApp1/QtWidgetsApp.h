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
    //
     //修改数据
    void on_change_Button_clicked() const;

    //同步数据
    void on_sync_Button_clicked() const;

};
