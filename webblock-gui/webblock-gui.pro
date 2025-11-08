#-------------------------------------------------
#
# Project created by QtCreator 2023
#-------------------------------------------------

QT += widgets core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = webblock-gui
TEMPLATE = app


CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp

HEADERS += \
    Database.h \
        mainwindow.h \
    hakkinda.h \
    giris.h \
    ayar.h


RESOURCES += \
    resources.qrc


DEFINES += QT_DEPRECATED_WARNINGS

target.path = /usr/bin

desktop_file.files = webblock-gui.desktop
desktop_file.path = /usr/share/applications/

icon.files = icons/webblock.svg
icon.path = /usr/share/icons/

INSTALLS += target desktop_file icon

DISTFILES += \
    webblock-gui.desktop
