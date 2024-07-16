#include "QtWidgetsApp.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QtWidgetsApp w;
    w.show();
    return a.exec();
}
