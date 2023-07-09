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
    bool processPacket(pcpp::Packet & packet);
    pcpp::RawPacket &getRawPacket(size_t index);
    pcpp::Packet &getParsedPacket(size_t index);
    std::vector<pcpp::RawPacket>::iterator rawPacketsBegin();
    std::vector<pcpp::RawPacket>::iterator rawPacketsEnd();
    std::vector<pcpp::Packet>::iterator parsedPacketsBegin();
    std::vector<pcpp::Packet>::iterator parsedPacketsEnd();

    static const pcpp::Layer *getFirstLayer(const pcpp::Packet & packet);
    static QString getProtocolTypeAsString(pcpp::ProtocolType protocolType);
    static std::tuple<QString, QString> getEthTuple(const pcpp::Packet & packet);
    static std::tuple<QString, QString> getIpTuple(const pcpp::Packet & packet);
    static std::tuple<uint16_t, uint16_t> getLayer4Tuple(const pcpp::Packet & packet);

private:
    pcpp::IFileReaderDevice *reader;
    std::vector<pcpp::RawPacket> rawPackets;
    std::vector<pcpp::Packet> parsedPackets;
};

#endif // PCAPPLUSPLUS_H