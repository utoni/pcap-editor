#include "pcapplusplus.h"

#include <chrono>
#include <EthLayer.h>
#include <exception>
#include <IPLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <random>
#include <SystemUtils.h>
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

pcpp::RawPacket& PcapPlusPlus::getRawPacket(size_t index)
{
    return rawPackets.at(index);
}

pcpp::Packet& PcapPlusPlus::getParsedPacket(size_t index)
{
    return parsedPackets.at(index);
}

pcpp::LinkLayerType PcapPlusPlus::getLinkLayer()
{
    const auto& pcap_file_reader = dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);

    if (pcap_file_reader)
        return pcap_file_reader->getLinkLayerType();
    else
        return pcpp::LinkLayerType::LINKTYPE_NULL;
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

bool PcapPlusPlus::randomizeEth(size_t index, bool isSourceEth)
{
    std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());
    auto retval = false;
    auto parsedPacket = pcpp::Packet(&getRawPacket(index));
    auto * ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

    if (ethLayer) {
        std::uniform_int_distribution<unsigned long long int> ethDistribution(0, 0xFFFFFFFFFFFFFFFF);
        unsigned long long int newEthAddr = ethDistribution(generator);

        if (isSourceEth)
            std::memcpy(ethLayer->getEthHeader()->srcMac, reinterpret_cast<uint8_t *>(&newEthAddr), 6);
        else
            std::memcpy(ethLayer->getEthHeader()->dstMac, reinterpret_cast<uint8_t *>(&newEthAddr), 6);

        retval = true;
    }

    parsedPackets[index] = parsedPacket;

    return retval;
}

bool PcapPlusPlus::randomizeIp(size_t index, bool isSourceIp)
{
    std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());
    auto retval = false;
    auto parsedPacket = pcpp::Packet(&getRawPacket(index));
    auto * ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    auto * ip6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();

    if (ip4Layer) {
        std::uniform_int_distribution<unsigned int> ip4Distribution(0, 0xFFFFFFFF);

        if (isSourceIp)
            ip4Layer->getIPv4Header()->ipSrc = pcpp::IPv4Address(ip4Distribution(generator)).toInt();
        else
            ip4Layer->getIPv4Header()->ipDst = pcpp::IPv4Address(ip4Distribution(generator)).toInt();

        retval = true;
    }

    if (ip6Layer) {
        std::uniform_int_distribution<unsigned long long int> ip6Distribution(0, 0xFFFFFFFFFFFFFFFF);
        unsigned long long int newIp6Addr[2] { ip6Distribution(generator), ip6Distribution(generator) };

        if (isSourceIp)
            std::memcpy(ip6Layer->getIPv6Header()->ipSrc, reinterpret_cast<uint8_t *>(newIp6Addr), 16);
        else
            std::memcpy(ip6Layer->getIPv6Header()->ipDst, reinterpret_cast<uint8_t *>(newIp6Addr), 16);

        retval = true;
    }

    parsedPackets[index] = parsedPacket;

    return retval;
}

bool PcapPlusPlus::randomizePort(size_t index, bool isSourcePort)
{
    std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());
    auto retval = false;
    auto parsedPacket = pcpp::Packet(&getRawPacket(index));
    auto * udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    auto * tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    std::uniform_int_distribution<unsigned short> portDistribution(0, 0xFFFF);

    if (udpLayer) {
        if (isSourcePort)
            udpLayer->getUdpHeader()->portSrc = portDistribution(generator);
        else
            udpLayer->getUdpHeader()->portDst = portDistribution(generator);

        retval = true;
    }

    if (tcpLayer) {
        if (isSourcePort)
            tcpLayer->getTcpHeader()->portSrc = portDistribution(generator);
        else
            tcpLayer->getTcpHeader()->portDst = portDistribution(generator);

        retval = true;
    }

    parsedPackets[index] = parsedPacket;

    return retval;
}

bool PcapPlusPlus::setEth(size_t index, const std::string & eth, bool isSourceEth)
{
    auto retval = false;
    auto parsedPacket = pcpp::Packet(&getRawPacket(index));
    auto * ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();

    if (ethLayer) {
        pcpp::MacAddress mac(eth);

        if (isSourceEth)
            std::memcpy(ethLayer->getEthHeader()->srcMac, mac.getRawData(), 6);
        else
            std::memcpy(ethLayer->getEthHeader()->dstMac, mac.getRawData(), 6);

        retval = true;
    }

    parsedPackets[index] = parsedPacket;

    return retval;
}

bool PcapPlusPlus::setIp(size_t index, const std::string & ip, bool isSourceIp)
{
    auto retval = false;
    auto parsedPacket = pcpp::Packet(&getRawPacket(index));
    auto * ip4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    auto * ip6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();

    if (ip4Layer) {
        pcpp::IPv4Address addr(ip);

        if (isSourceIp)
            ip4Layer->getIPv4Header()->ipSrc = addr.toInt();
        else
            ip4Layer->getIPv4Header()->ipDst = addr.toInt();

        retval = true;
    }

    if (ip6Layer) {
        pcpp::IPv6Address addr(ip);

        if (isSourceIp)
            std::memcpy(ip6Layer->getIPv6Header()->ipSrc, addr.toBytes(), 16);
        else
            std::memcpy(ip6Layer->getIPv6Header()->ipDst, addr.toBytes(), 16);

        retval = true;
    }

    parsedPackets[index] = parsedPacket;

    return retval;
}

bool PcapPlusPlus::setPort(size_t index, const std::string & port, bool isSourcePort)
{
    auto retval = false;
    auto parsedPacket = pcpp::Packet(&getRawPacket(index));
    auto * udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    auto * tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    const unsigned short portNum = pcpp::hostToNet16(std::stoi(port));

    if (udpLayer) {
        if (isSourcePort)
            udpLayer->getUdpHeader()->portSrc = portNum;
        else
            udpLayer->getUdpHeader()->portDst = portNum;

        retval = true;
    }

    if (tcpLayer) {
        if (isSourcePort)
            tcpLayer->getTcpHeader()->portSrc = portNum;
        else
            tcpLayer->getTcpHeader()->portDst = portNum;

        retval = true;
    }

    parsedPackets[index] = parsedPacket;

    return retval;
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
