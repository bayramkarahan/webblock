QT += core network
CONFIG += console c++11
TARGET=webblock-service

TEMPLATE = app
SOURCES += main.cpp \
    webblockcore.cpp
HEADERS += \
    webblockcore.h
unix:LIBS += -lpcap
#sudo apt install libpcap-dev
# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
target.path = /usr/bin

script.files = script/*
script.path = /usr/share/webblock/script

data.files = data/*
data.path = /usr/share/webblock/data


webblockservice.files = webblock.service
webblockservice.path = /lib/systemd/system/


INSTALLS += target script webblockservice data
