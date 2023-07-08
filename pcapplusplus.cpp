#include "pcapplusplus.h"

#include <EthLayer.h>
#include <exception>
#include <IPLayer.h>
#include <TcpLayer.h>
#include <tuple>
#include <UdpLayer.h>

PcapPlusPlus::PcapPlusPlus(std::string fileName) : rawPackets(), parsedPackets()
{
    reader = pcpp::IFileReaderDevice::getReader(fileName);

    if (!reader) {
        std::string err("PCAP Reader failed for: " + fileName);
        throw std::runtime_error(err);
    }

    if (!reader->open()) {
        std::string err("PCAP Open failed for: " + fileName);
        throw std::runtime_error(err);
    }
}

PcapPlusPlus::~PcapPlusPlus()
{
    if (reader) {
        reader->close();
        delete reader;
        reader = nullptr;
    }
}

bool PcapPlusPlus::openPcap()
{
    if (!reader)
        return false;

    if (reader->isOpened())
        throw std::runtime_error("PCAP File already open. Close it first.");

    return reader->open();
}

void PcapPlusPlus::closePcap()
{
    if (reader)
        reader->close();
}

bool PcapPlusPlus::setFilter(QString filter)
{
    if (reader)
        return reader->setFilter(filter.toStdString());

    return false;
}

bool PcapPlusPlus::processPacket(pcpp::Packet & packet)
{
    pcpp::RawPacket rawPacket;

    if (!reader)
        return false;

    if (reader->getNextPacket(rawPacket)) {
        rawPackets.emplace_back(std::move(rawPacket));

        pcpp::Packet parsedPacket(&rawPackets.back(), false);
        packet = parsedPacket;

        parsedPackets.emplace_back(std::move(parsedPacket));

        return true;
    }

    return false;
}

pcpp::RawPacket &PcapPlusPlus::getRawPacket(size_t index)
{
    return rawPackets.at(index);
}

pcpp::Packet &PcapPlusPlus::getParsedPacket(size_t index)
{
    return parsedPackets.at(index);
}

std::vector<pcpp::RawPacket>::iterator PcapPlusPlus::rawPacketsBegin()
{
    return rawPackets.begin();
}

std::vector<pcpp::RawPacket>::iterator PcapPlusPlus::rawPacketsEnd()
{
    return rawPackets.end();
}

std::vector<pcpp::Packet>::iterator PcapPlusPlus::parsedPacketsBegin()
{
    return parsedPackets.begin();
}

std::vector<pcpp::Packet>::iterator PcapPlusPlus::parsedPacketsEnd()
{
    return parsedPackets.end();
}

bool PcapPlusPlus::getPcapStatistics(pcpp::IFileDevice::PcapStats & stats)
{
    if (reader) {
        reader->getStatistics(stats);
        return true;
    }

    return false;
}

const pcpp::Layer *PcapPlusPlus::getFirstLayer(const pcpp::Packet & packet)
{
    const auto *curLayer = packet.getFirstLayer();

    if (curLayer == nullptr)
    {
        throw std::runtime_error("No Ethernet Layer found.");
        return nullptr;
    }

    return curLayer;
}

QString PcapPlusPlus::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::ARP:
        return "ARP";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::IPv6:
        return "IPv6";
    case pcpp::TCP:
        return "TCP";
    case pcpp::UDP:
        return "UDP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    case pcpp::UnknownProtocol:
        return "Unknown Protocol";
    default:
        return "Unknown";
    }
}

std::tuple<QString, QString> PcapPlusPlus::getEthTuple(const pcpp::Packet & packet)
{
    const auto *ethernetLayer = packet.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer == NULL)
        return std::make_tuple("", "");

    return std::make_tuple(QString::fromStdString(ethernetLayer->getSourceMac().toString()), QString::fromStdString(ethernetLayer->getDestMac().toString()));
}

std::tuple<QString, QString> PcapPlusPlus::getIpTuple(const pcpp::Packet & packet)
{
    const auto *ipLayer = packet.getLayerOfType<pcpp::IPLayer>();
    if (ipLayer == NULL)
        return std::make_tuple("", "");

    return std::make_tuple(QString::fromStdString(ipLayer->getSrcIPAddress().toString()), QString::fromStdString(ipLayer->getDstIPAddress().toString()));
}

std::tuple<uint16_t, uint16_t> PcapPlusPlus::getLayer4Tuple(const pcpp::Packet & packet)
{
    const auto *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer != NULL)
        return std::make_tuple(udpLayer->getSrcPort(), udpLayer->getDstPort());

    const auto *tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer != NULL)
        return std::make_tuple(tcpLayer->getSrcPort(), tcpLayer->getDstPort());

    return std::make_tuple(0, 0);
}
