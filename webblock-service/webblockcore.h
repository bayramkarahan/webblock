#ifndef WEBBLOCKCORE_H
#define WEBBLOCKCORE_H

#include <QObject>
#include <QFileSystemWatcher>
#include <QMap>
#include <QSet>
#include <QTimer>
#include <QMutex>
#include <QDateTime>
#include <QCoreApplication>

extern "C" {
#include <pcap/pcap.h>
}

struct IpInfo {
    QSet<QString> domains;
    qint64 expiresAt; // epoch seconds
};

struct PendingQuery {
    QString qname;
    qint64 seenAt;
    QString srcIp;
    quint16 srcPort;
};

class NetsentinelCore : public QObject
{
    Q_OBJECT
public:
    explicit NetsentinelCore(QObject *parent = nullptr);
    ~NetsentinelCore();
    void start();

private:
    QString dataPath;
    QFileSystemWatcher watcher;
    QSet<QString> blockDomains; // lower-case patterns
    QMap<QString, IpInfo> ipMap; // ip string -> info
    QMap<uint16_t, PendingQuery> pendingById; // DNS transaction id -> query
    QMutex mapMutex;
    QTimer cleanupTimer;

    pcap_t *pcapHandle = nullptr;
    QString iface;
    //void handlePacket(const struct pcap_pkthdr *h, const unsigned char *bytes);

    void loadRules();
    void setupPcap();
    static void pcapCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void handlePacket(const struct pcap_pkthdr *h, const u_char *bytes);
    void parseDnsPacket(const u_char *payload, int len, const char *srcIp, quint16 srcPort, bool isResponse, bool isIpv6);
    void addBlockIp(const QString &ip);
    void removeBlockIp(const QString &ip);
    void cleanupExpired();
    qint64 nowSeconds() const { return QDateTime::currentSecsSinceEpoch(); }

    void runCmd(const QStringList &args);
    static bool domainMatches(const QString &pattern, const QString &name);

    // 🟢 Yeni
    void initialBlockDomains();
};

#endif // WEBBLOCKCORE_H
