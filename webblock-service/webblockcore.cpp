#include "webblockcore.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>
#include <QDebug>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <thread>
#include <cstring>
#include <netdb.h>
#include <QtConcurrent/QtConcurrent>
#include <QHostInfo>
#include <QHostAddress>
#include <csignal>
#include <chrono>

static bool stopFlag = false;

// Ctrl+C yakalama
void sigintHandler(int) {
    qInfo() << "SIGINT received, stopping...";
    stopFlag = true;
    QCoreApplication::quit();
}

NetsentinelCore::NetsentinelCore(QObject *parent) : QObject(parent)
{
    dataPath="/usr/share/webblock/data/";
    std::signal(SIGINT, sigintHandler);
    std::signal(SIGTERM, sigintHandler);
    std::signal(SIGQUIT, sigintHandler);

    connect(&watcher, &QFileSystemWatcher::fileChanged, this, [this](const QString &){
        qInfo() << "webblock.json changed, reload";
        loadRules();
    });

    connect(&cleanupTimer, &QTimer::timeout, this, &NetsentinelCore::cleanupExpired);
    cleanupTimer.start(5000); // clean every 5s

    connect(qApp, &QCoreApplication::aboutToQuit, [this](){
        stopFlag = true;
        QMutexLocker lk(&mapMutex);
        for (const QString &ip : ipMap.keys()) {
            removeBlockIp(ip);
        }
        ipMap.clear();
        qInfo() << "All blocked IPs removed on quit signal.";
    });
}

NetsentinelCore::~NetsentinelCore()
{
    stopFlag = true;
    if (pcapHandle) pcap_close(pcapHandle);

    QMutexLocker lk(&mapMutex);
    for (const QString &ip : ipMap.keys()) {
        removeBlockIp(ip);
    }
    ipMap.clear();
    qInfo() << "All blocked IPs removed on exit.";
}

void NetsentinelCore::start()
{
    loadRules();

    // ensure ipset exist (v4 + v6)
    runCmd(QStringList() << "ipset" << "create" << "blocklist" << "hash:ip" << "family" << "inet" << "-exist");
    runCmd(QStringList() << "ipset" << "create" << "blocklist6" << "hash:ip" << "family" << "inet6" << "-exist");

    // legacy iptables kuralları
    runCmd(QStringList() << "update-alternatives" << "--set" << "iptables" << "/usr/sbin/iptables-legacy");
    runCmd(QStringList() << "update-alternatives" << "--set" << "ip6tables" << "/usr/sbin/ip6tables-legacy");
    runCmd(QStringList() << "iptables" << "-I" << "OUTPUT" << "-m" << "set" << "--match-set" << "blocklist" << "dst" << "-j" << "DROP");
    runCmd(QStringList() << "ip6tables" << "-I" << "OUTPUT" << "-m" << "set" << "--match-set" << "blocklist6" << "dst" << "-j" << "DROP");

    initialBlockDomains();
    setupPcap();
}

void NetsentinelCore::loadRules()
{
    QFile f(dataPath+"webblock.json");
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "webblock.json open failed";
        return;
    }

    const QByteArray raw = f.readAll();
    f.close();

    QSet<QString> newBlocks;

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
    if (err.error != QJsonParseError::NoError) {
        qWarning() << "webblock.json parse error:" << err.errorString();
        return;
    }

    // New format: top-level array of objects { index, selectedWord, word }
    if (doc.isArray()) {
        QJsonArray arr = doc.array();
        for (const QJsonValue &v : arr) {
            if (!v.isObject()) continue;
            QJsonObject obj = v.toObject();
            bool sel = obj.value(QStringLiteral("selectedWord")).toBool(false);
            QString w = obj.value(QStringLiteral("word")).toString().trimmed().toLower();
            if (sel && !w.isEmpty()) newBlocks.insert(w);
        }
    }
    // Backwards compatible: { "block": ["a","b"] }
    else if (doc.isObject()) {
        QJsonObject obj = doc.object();
        QJsonValue bv = obj.value(QStringLiteral("block"));
        if (bv.isArray()) {
            QJsonArray barr = bv.toArray();
            for (const QJsonValue &vv : barr) {
                QString d = vv.toString().trimmed().toLower();
                if (!d.isEmpty()) newBlocks.insert(d);
            }
        } else {
            qWarning() << "webblock.json: object found but no 'block' array; expecting array-of-objects or {\"block\":[]}";
        }
    } else {
        qWarning() << "webblock.json: unexpected top-level JSON type";
    }

    {
        QMutexLocker lk(&mapMutex);
        blockDomains = newBlocks;
    }
    // ensure watcher is watching (addPath is safe to call multiple times)
    watcher.addPath(dataPath+"webblock.json");
    qInfo() << "Block list loaded:" << blockDomains;
}

bool NetsentinelCore::domainMatches(const QString &pattern, const QString &name) {
    if (name == pattern) return true;
    if (name.endsWith("." + pattern)) return true;
    return false;
}

void NetsentinelCore::initialBlockDomains()
{
    QSet<QString> domainsCopy;
    {
        QMutexLocker lk(&mapMutex);
        domainsCopy = blockDomains;
    }

    for (const QString &domain : domainsCopy) {
        QtConcurrent::run([this, domain]() {
            // IPv4
            QHostInfo info4 = QHostInfo::fromName(domain);
            for (const QHostAddress &addr : info4.addresses()) {
                if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
                    QString ip = addr.toString();
                    addBlockIp(ip);
                    qInfo() << "[INITIAL BLOCK IPv4]" << ip << "for domain" << domain;
                }
            }
            // IPv6
            QHostInfo info6 = QHostInfo::fromName(domain);
            for (const QHostAddress &addr : info6.addresses()) {
                if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
                    QString ip = addr.toString();
                    addBlockIp(ip);
                    qInfo() << "[INITIAL BLOCK IPv6]" << ip << "for domain" << domain;
                }
            }
        });
    }
}

void NetsentinelCore::setupPcap()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs) {
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (!(d->flags & PCAP_IF_LOOPBACK)) { iface = d->name; break; }
        }
        pcap_freealldevs(alldevs);
    }
    if (iface.isEmpty()) iface = "any";

    pcapHandle = pcap_open_live(iface.toUtf8().constData(), 65536, 1, 1000, errbuf);
    if (!pcapHandle) {
        qWarning() << "pcap open failed:" << errbuf;
        return;
    }

    struct bpf_program fp;
    const char *filter = "udp port 53 or (tcp[tcpflags] & tcp-syn != 0) or udp dst port 443";
    if (pcap_compile(pcapHandle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        qWarning() << "pcap_compile failed";
    } else {
        pcap_setfilter(pcapHandle, &fp);
        pcap_freecode(&fp);
    }

    std::thread([this](){
        while (!stopFlag) {
            pcap_dispatch(pcapHandle, 10, &NetsentinelCore::pcapCallback, reinterpret_cast<u_char*>(this));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        qInfo() << "Packet capture thread stopped";
    }).detach();

    qInfo() << "pcap started on iface" << iface;
}

static QString readQName(const u_char *buf, int bufLen, int &offset) {
    QString name;
    int jumped = 0;
    while (offset < bufLen) {
        uint8_t l = buf[offset];
        if (l == 0) { offset++; break; }
        if ((l & 0xC0) == 0xC0) { // pointer
            if (offset + 1 >= bufLen) break;
            int ptr = ((l & 0x3F) << 8) | buf[offset+1];
            if (!jumped) jumped = offset + 2;
            offset = ptr;
            continue;
        } else {
            offset++;
            for (int i=0;i<l && offset<bufLen;i++) { name.append(QChar(buf[offset++])); }
            if (offset < bufLen && buf[offset] != 0) name.append('.');
        }
    }
    if (jumped) offset = jumped;
    return name.toLower();
}



// Callback
void NetsentinelCore::pcapCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    auto self = reinterpret_cast<NetsentinelCore*>(user);
    if (self) self->handlePacket(h, bytes);
}

void NetsentinelCore::handlePacket(const struct pcap_pkthdr *h, const u_char *bytes)
{
    if (h->caplen < 14) return;
    const u_char *eth_payload = bytes + 14;
    // peek first nibble to guess IPv4/IPv6
    int version = (eth_payload[0] >> 4) & 0xF;
    if (version == 4) {
        const struct ip *iph = (const struct ip*)eth_payload;
        int ihl = iph->ip_hl * 4;
        if (iph->ip_p == IPPROTO_UDP) {
            if (h->caplen < 14 + ihl + 8) return;
            const u_char *udp = eth_payload + ihl;
            uint16_t sport = ntohs(*(uint16_t*)(udp));
            uint16_t dport = ntohs(*(uint16_t*)(udp+2));
            if (sport == 53 || dport == 53) {
                bool isResponse = (sport == 53);
                int dns_off = 14 + ihl + 8;
                int dns_len = h->caplen - dns_off;
                char srcbuf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &iph->ip_src, srcbuf, sizeof(srcbuf));
                quint16 srcport = sport;
                parseDnsPacket(bytes + dns_off, dns_len, srcbuf, srcport, isResponse, false);
            } else if (dport == 443) {
                // UDP QUIC
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &iph->ip_dst, buf, sizeof(buf));
                QString dst = QString::fromUtf8(buf);
                bool shouldBlock = false;
                {
                    QMutexLocker lk(&mapMutex);
                    auto it = ipMap.find(dst);
                    if (it != ipMap.end()) {
                        for (const QString &d : it->domains) {
                            for (const QString &pat : blockDomains) {
                                if (domainMatches(pat, d)) { shouldBlock = true; break; }
                            }
                            if (shouldBlock) break;
                        }
                    }
                }
                if (shouldBlock) {
                    addBlockIp(dst);
                    qInfo() << "[BLOCK-QUIC]" << dst << "matched blacklist";
                }
            }
        } else if (iph->ip_p == IPPROTO_TCP) {
            const u_char *tcp = eth_payload + ihl;
            if (h->caplen < 14 + ihl + 20) return;
            uint8_t flags = tcp[13];
            if (flags & 0x02) {
                char buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &iph->ip_dst, buf, sizeof(buf));
                QString dst = QString::fromUtf8(buf);
                bool shouldBlock = false;
                {
                    QMutexLocker lk(&mapMutex);
                    auto it = ipMap.find(dst);
                    if (it != ipMap.end()) {
                        for (const QString &d : it->domains) {
                            for (const QString &pat : blockDomains) {
                                if (domainMatches(pat, d)) { shouldBlock = true; break; }
                            }
                            if (shouldBlock) break;
                        }
                    }
                }
                if (shouldBlock) {
                    addBlockIp(dst);
                    qInfo() << "[BLOCK]" << dst << "matched blacklist";
                }
            }
        }
    } else if (version == 6) {
        if (h->caplen < 14 + (int)sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr *ip6h = (const struct ip6_hdr*)(eth_payload);
        uint8_t nexthdr = ip6h->ip6_nxt;
        // basic IPv6 payload pointer
        const u_char *payload = eth_payload + sizeof(struct ip6_hdr);
        int payload_len = h->caplen - 14 - sizeof(struct ip6_hdr);
        // Note: doesn't handle extension headers comprehensively — prototype handles common cases where UDP/TCP directly follow
        if (nexthdr == IPPROTO_UDP && payload_len >= 8) {
            const struct udphdr *udph = (const struct udphdr*)payload;
            uint16_t sport = ntohs(udph->uh_sport);
            uint16_t dport = ntohs(udph->uh_dport);
            if (sport == 53 || dport == 53) {
                bool isResponse = (sport == 53);
                int dns_off = 14 + sizeof(struct ip6_hdr) + 8;
                int dns_len = h->caplen - dns_off;
                char srcbuf[INET6_ADDRSTRLEN]; inet_ntop(AF_INET6, &ip6h->ip6_src, srcbuf, sizeof(srcbuf));
                parseDnsPacket(bytes + dns_off, dns_len, srcbuf, sport, isResponse, true);
            } else if (dport == 443) {
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6h->ip6_dst, buf, sizeof(buf));
                QString dst = QString::fromUtf8(buf);
                bool shouldBlock = false;
                {
                    QMutexLocker lk(&mapMutex);
                    auto it = ipMap.find(dst);
                    if (it != ipMap.end()) {
                        for (const QString &d : it->domains) {
                            for (const QString &pat : blockDomains) {
                                if (domainMatches(pat, d)) { shouldBlock = true; break; }
                            }
                            if (shouldBlock) break;
                        }
                    }
                }
                if (shouldBlock) {
                    addBlockIp(dst);
                    qInfo() << "[BLOCK-QUIC6]" << dst << "matched blacklist";
                }
            }
        } else if (nexthdr == IPPROTO_TCP && payload_len >= 20) {
            const struct tcphdr *tcph = (const struct tcphdr*)payload;
            uint8_t flags = ((const u_char*)payload)[13];
            if (flags & 0x02) {
                char buf[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6h->ip6_dst, buf, sizeof(buf));
                QString dst = QString::fromUtf8(buf);
                bool shouldBlock = false;
                {
                    QMutexLocker lk(&mapMutex);
                    auto it = ipMap.find(dst);
                    if (it != ipMap.end()) {
                        for (const QString &d : it->domains) {
                            for (const QString &pat : blockDomains) {
                                if (domainMatches(pat, d)) { shouldBlock = true; break; }
                            }
                            if (shouldBlock) break;
                        }
                    }
                }
                if (shouldBlock) {
                    addBlockIp(dst);
                    qInfo() << "[BLOCK6]" << dst << "matched blacklist";
                }
            }
        }
    }
}


void NetsentinelCore::parseDnsPacket(const u_char *payload, int len, const char *srcIp, quint16 srcPort, bool isResponse, bool isIpv6)
{
    if (len < 12) return;
    const uint8_t *p = payload;
    uint16_t id = ntohs(*(uint16_t*)(p));
    uint16_t qdcount = ntohs(*(uint16_t*)(p+4));
    uint16_t ancount = ntohs(*(uint16_t*)(p+6));
    int offset = 12;
    QString qname;
    if (qdcount > 0) {
        qname = readQName(payload, len, offset);
        offset += 4; // qtype + qclass
    }
    if (!isResponse) {
        PendingQuery pq; pq.qname = qname; pq.seenAt = nowSeconds(); pq.srcIp = QString::fromUtf8(srcIp); pq.srcPort = srcPort;
        QMutexLocker lk(&mapMutex);
        pendingById[id] = pq;
        return;
    }
    for (int i=0;i<ancount;i++) {
        if (offset + 10 > len) break;
        if ((payload[offset] & 0xC0) == 0xC0) offset += 2;
        else { while (offset < len && payload[offset] != 0) { int l = payload[offset]; offset += 1 + l; } offset += 1; }
        if (offset + 10 > len) break;
        uint16_t atype = ntohs(*(uint16_t*)(payload+offset)); offset += 2;
        offset += 2; // class
        uint32_t ttl = ntohl(*(uint32_t*)(payload+offset)); offset += 4;
        uint16_t rdlen = ntohs(*(uint16_t*)(payload+offset)); offset += 2;
        if (offset + rdlen > len) break;
        if (atype == 1 && rdlen == 4) { // A
            char ipbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, payload+offset, ipbuf, sizeof(ipbuf));
            QString ip = QString::fromUtf8(ipbuf);
            QString domain;
            {
                QMutexLocker lk(&mapMutex);
                if (pendingById.contains(id)) domain = pendingById[id].qname;
            }
            if (domain.isEmpty()) domain = qname;
            qint64 expireAt = nowSeconds() + (ttl?ttl:60);
            {
                QMutexLocker lk(&mapMutex);
                IpInfo &info = ipMap[ip];
                if (!domain.isEmpty()) info.domains.insert(domain);
                info.expiresAt = expireAt;
            }
            qInfo() << "[DNS]" << domain << "->" << ip << "ttl" << ttl;
            // immediate block if matches
            bool matched = false;
            {
                QMutexLocker lk(&mapMutex);
                for (const QString &pat : blockDomains) {
                    if (domainMatches(pat, domain)) { matched = true; break; }
                }
            }
            if (matched) {
                addBlockIp(ip);
                qInfo() << "[IMMEDIATE BLOCK]" << ip << "for domain" << domain;
            }
        } else if (atype == 28 && rdlen == 16) { // AAAA
            char ipbuf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, payload+offset, ipbuf, sizeof(ipbuf));
            QString ip = QString::fromUtf8(ipbuf);
            QString domain;
            {
                QMutexLocker lk(&mapMutex);
                if (pendingById.contains(id)) domain = pendingById[id].qname;
            }
            if (domain.isEmpty()) domain = qname;
            qint64 expireAt = nowSeconds() + (ttl?ttl:60);
            {
                QMutexLocker lk(&mapMutex);
                IpInfo &info = ipMap[ip];
                if (!domain.isEmpty()) info.domains.insert(domain);
                info.expiresAt = expireAt;
            }
            qInfo() << "[DNS] AAAA" << domain << "->" << ip << "ttl" << ttl;
            bool matched = false;
            {
                QMutexLocker lk(&mapMutex);
                for (const QString &pat : blockDomains) {
                    if (domainMatches(pat, domain)) { matched = true; break; }
                }
            }
            if (matched) {
                addBlockIp(ip);
                qInfo() << "[IMMEDIATE BLOCK]" << ip << "for domain" << domain;
            }
        }
        offset += rdlen;
    }
    {
        QMutexLocker lk(&mapMutex);
        pendingById.remove(id);
    }
}

// add / remove
void NetsentinelCore::addBlockIp(const QString &ip)
{
    if (ip.contains(':')) {
        runCmd(QStringList() << "ipset" << "add" << "blocklist6" << ip << "-exist");
    } else {
        runCmd(QStringList() << "ipset" << "add" << "blocklist" << ip << "-exist");
    }
}

void NetsentinelCore::removeBlockIp(const QString &ip)
{
    if (ip.contains(':')) {
        runCmd(QStringList() << "ipset" << "del" << "blocklist6" << ip);
    } else {
        runCmd(QStringList() << "ipset" << "del" << "blocklist" << ip);
    }
}

void NetsentinelCore::cleanupExpired()
{
    qint64 now = nowSeconds();
    QList<QString> toRemove;
    {
        QMutexLocker lk(&mapMutex);
        for (auto it = ipMap.begin(); it != ipMap.end(); ++it) {
            if (it->expiresAt > 0 && it->expiresAt < now) toRemove.append(it.key());
        }
        for (const QString &k : toRemove) ipMap.remove(k);
        QList<uint16_t> old;
        for (auto it = pendingById.begin(); it != pendingById.end(); ++it) {
            if (it.value().seenAt + 10 < now) old.append(it.key());
        }
        for (auto id : old) pendingById.remove(id);
    }
    for (const QString &ip : toRemove) {
        removeBlockIp(ip);
        qInfo() << "[CLEAN]" << ip << "removed (TTL expired)";
    }
}

void NetsentinelCore::runCmd(const QStringList &args)
{
    QProcess p;
    p.start(args.first(), args.mid(1));
    p.waitForFinished(2000);
}
