#-------------------------------------------------
#
# Project created by QtCreator 2023
#-------------------------------------------------

QT += widgets network core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = webblock-tray
TEMPLATE = app


CONFIG += c++11

SOURCES += \
        main.cpp \
        mainwindow.cpp

HEADERS += \
        mainwindow.h


RESOURCES += \
    resources.qrc


DEFINES += QT_DEPRECATED_WARNINGS

target.path = /usr/bin

icon.files = icons/webblock.svg
icon.path = /usr/share/icons

auto_start.files = autostart-webblock-tray.desktop
auto_start.path = /etc/xdg/autostart/

INSTALLS += target icon  auto_start

DISTFILES += \
    autostart-webblock-tray.desktop
