QT += core
QT -= gui

CONFIG += c++11

TARGET = pcap_proj
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    scanner.cpp

HEADERS += \
    scanner.h

LIBS += -lpcap
