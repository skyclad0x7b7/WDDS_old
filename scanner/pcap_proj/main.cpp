#include <QCoreApplication>
#include "scanner.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    char device[256];
    int channel;
    char cmd[300];

    cout << "[*] Please Input Device : ";
    cin >> device;
    cout << "[*] Please Input Channel : ";
    cin >> channel;
    sprintf(cmd, "iwconfig %s channel %d", device, channel);
    system(cmd);

    Scanner sc(device);
    sc.startScan();

    getchar();
    getchar();

    sc.stopScan();

    getchar();

    sc.startScan();

    getchar();

    sc.stopScan();

    return a.exec();
}
