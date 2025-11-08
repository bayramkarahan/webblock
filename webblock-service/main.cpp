#include <QCoreApplication>
#include "webblockcore.h"
int main(int argc, char **argv)
    {
    QCoreApplication a(argc, argv);
    NetsentinelCore core; core.start();



    return a.exec();
    }
