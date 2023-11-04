#ifndef PCAPPLUSPLUS_H
#define PCAPPLUSPLUS_H

#include <Packet.h>
#include <PcapFileDevice.h>
#include <qstring.h>

class PcapPlusPlus
{
public:
    explicit PcapPlusPlus(std::string fileName);
    ~PcapPlusPlus();
    bool openPcap();
    void closePcap();
    bool setFilter(QString filter);
    bool processPacket(pcpp::Packet & packet);
    pcpp::RawPacket& getRawPacket(size_t index);
    pcpp::Packet& getParsedPacket(size_t index);
    pcpp::LinkLayerType getLinkLayer();
    std::vector<pcpp::RawPacket>::iterator rawPacketsBegin();
    std::vector<pcpp::RawPacket>::iterator rawPacketsEnd();
    std::vector<pcpp::Packet>::iterator parsedPacketsBegin();
    std::vector<pcpp::Packet>::iterator parsedPacketsEnd();
    bool randomizeEth(size_t index, bool isSourceEth);
    bool randomizeIp(size_t index, bool isSourceIp);
    bool randomizePort(size_t index, bool isSourcePort);
    bool setEth(size_t index, const std::string & eth, bool isSourceIp);
    bool setIp(size_t index, const std::string & ip, bool isSourceIp);
    bool setPort(size_t index, const std::string & port, bool isSourceIp);
    void fixupHeaders(size_t index);
    bool getPcapStatistics(pcpp::IFileDevice::PcapStats & stats);
    double getFirstPacketTimestamp() { return firstPacketTs; }

    static const pcpp::Layer *getFirstLayer(const pcpp::Packet & packet);
    static QString getProtocolTypeAsString(pcpp::ProtocolType protocolType);
    static std::tuple<QString, QString> getEthTuple(const pcpp::Packet & packet);
    static std::tuple<QString, QString> getIpTuple(const pcpp::Packet & packet);
    static std::tuple<uint16_t, uint16_t> getLayer4Tuple(const pcpp::Packet & packet);

private:
    double firstPacketTs = 0;
    pcpp::IFileReaderDevice *reader = nullptr;
    std::vector<pcpp::RawPacket> rawPackets;
    std::vector<pcpp::Packet> parsedPackets;
};

#endif // PCAPPLUSPLUS_H
