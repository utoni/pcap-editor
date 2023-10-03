#include "packetstablewidget.h"

PacketsTableWidget::PacketsTableWidget(QWidget *parent) : QTableWidget(parent)
{
    connect(this, &PacketsTableWidget::addRow, this, [&](PcapPlusPlus *ppp) {
        if (!addTableRow(ppp))
            throw std::runtime_error("Could not add row to table for packet");
    });

    connect(this, &PacketsTableWidget::updateRow, this, [&](size_t index, PcapPlusPlus *ppp) {
        if (!updateTableRow(index, ppp))
            throw std::runtime_error("Could not add row to table for packet");
    });
}

void PacketsTableWidget::randomizeLayerItem(PcapPlusPlus *ppp)
{
    if (!ppp)
        throw std::runtime_error("Can not randomize, no packets available");

    const auto & y = currentRow();
    const auto & col = currentColumn() + 1;

    if (isEthernetSrcColumn(col) || isEthernetDstColumn(col)) {
        ppp->randomizeEth(y, isEthernetSrcColumn(col));
    } else if (isIpSrcColumn(col) || isIpDstColumn(col)) {
        ppp->randomizeIp(y, isIpSrcColumn(col));
    } else if (isPortSrcColumn(col) || isPortDstColumn(col)) {
        ppp->randomizePort(y, isPortSrcColumn(col));
    } else throw std::runtime_error("BUG: No supported column selected");

    emit updateRow(y, ppp);
}

void PacketsTableWidget::setLayerItem(QTableWidgetItem *item, PcapPlusPlus *ppp, bool isProcessing)
{
    if (!item || !ppp)
        return;

    const auto & y = currentRow();
    const auto & col = currentColumn() + 1;
    const auto & text = item->text().toStdString();

    if (isEthernetSrcColumn(col) || isEthernetDstColumn(col)) {
        ppp->setEth(y, text, isEthernetSrcColumn(col));
    } else if (isIpSrcColumn(col) || isIpDstColumn(col)) {
        ppp->setIp(y, text, isIpSrcColumn(col));
    } else if (isPortSrcColumn(col) || isPortDstColumn(col)) {
        ppp->setPort(y, text, isPortSrcColumn(col));
    }

    if (isProcessing)
        return;
    emit updateRow(y, ppp);
}

bool PacketsTableWidget::addTableRow(PcapPlusPlus *ppp)
{
    QTableWidgetItem* itemRelativeTime = new QTableWidgetItem();
    QTableWidgetItem* itemFrameLength = new QTableWidgetItem();
    QTableWidgetItem* itemFirstLayerProtocol = new QTableWidgetItem();
    QTableWidgetItem* itemSecondLayerProtocol = new QTableWidgetItem();
    QTableWidgetItem* itemThirdLayerProtocol = new QTableWidgetItem();
    QTableWidgetItem* itemSrcMac = new QTableWidgetItem();
    QTableWidgetItem* itemDstMac = new QTableWidgetItem();
    QTableWidgetItem* itemSrcIp = new QTableWidgetItem();
    QTableWidgetItem* itemDstIp = new QTableWidgetItem();
    QTableWidgetItem* itemSrcPort = new QTableWidgetItem();
    QTableWidgetItem* itemDstPort = new QTableWidgetItem();
    QTableWidgetItem* itemDesc = new QTableWidgetItem();

    if (!itemRelativeTime || !itemFrameLength || !itemFirstLayerProtocol || !itemSecondLayerProtocol || !itemThirdLayerProtocol
        || !itemSrcMac || !itemDstMac || !itemSrcIp || !itemDstIp || !itemSrcPort || ! itemDstPort || !itemDesc)
    {
        delete itemRelativeTime;
        delete itemFrameLength;
        delete itemFirstLayerProtocol;
        delete itemSecondLayerProtocol;
        delete itemThirdLayerProtocol;
        delete itemSrcMac;
        delete itemDstMac;
        delete itemSrcIp;
        delete itemDstIp;
        delete itemSrcPort;
        delete itemDstPort;
        delete itemDesc;

        return false;
    }

    insertRow(rowCount());
    setItem(rowCount() - 1, 0, itemRelativeTime);
    setItem(rowCount() - 1, 1, itemFrameLength);
    setItem(rowCount() - 1, 2, itemFirstLayerProtocol);
    setItem(rowCount() - 1, 3, itemSecondLayerProtocol);
    setItem(rowCount() - 1, 4, itemThirdLayerProtocol);
    setItem(rowCount() - 1, 5, itemSrcMac);
    setItem(rowCount() - 1, 6, itemDstMac);
    setItem(rowCount() - 1, 7, itemSrcIp);
    setItem(rowCount() - 1, 8, itemDstIp);
    setItem(rowCount() - 1, 9, itemSrcPort);
    setItem(rowCount() - 1, 10, itemDstPort);
    setItem(rowCount() - 1, 11, itemDesc);

    item(rowCount() - 1, 0)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    item(rowCount() - 1, 1)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    item(rowCount() - 1, 2)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    item(rowCount() - 1, 3)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    item(rowCount() - 1, 4)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    item(rowCount() - 1, 11)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);

    emit updateRow(rowCount() - 1, ppp);
    return true;
}

bool PacketsTableWidget::updateTableRow(size_t index, PcapPlusPlus *ppp)
{
    if (!ppp)
        return false;

    auto parsedPacket = pcpp::Packet(&ppp->getRawPacket(index));
    const auto *firstLayer = PcapPlusPlus::getFirstLayer(parsedPacket);
    const auto *secondLayer = firstLayer ? firstLayer->getNextLayer() : nullptr;
    const auto *thirdLayer = secondLayer ? secondLayer->getNextLayer() : nullptr;
    const auto ethTuple = PcapPlusPlus::getEthTuple(parsedPacket);
    const auto ipTuple = PcapPlusPlus::getIpTuple(parsedPacket);
    const auto l4Tuple = PcapPlusPlus::getLayer4Tuple(parsedPacket);

    if (!firstLayer)
        return false;

    item(index, 0)->setText(tr("%1").arg(parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec - static_cast<unsigned long long int>(ppp->getFirstPacketTimestamp())));
    item(index, 1)->setText(tr("%1").arg(parsedPacket.getRawPacket()->getFrameLength()));
    item(index, 2)->setText(tr("%1").arg(firstLayer ? PcapPlusPlus::getProtocolTypeAsString(firstLayer->getProtocol()) : ""));
    item(index, 3)->setText(tr("%1").arg(secondLayer ? PcapPlusPlus::getProtocolTypeAsString(secondLayer->getProtocol()) : ""));
    item(index, 4)->setText(tr("%1").arg(thirdLayer ? PcapPlusPlus::getProtocolTypeAsString(thirdLayer->getProtocol()) : ""));
    item(index, 5)->setText(tr("%1").arg(std::get<0>(ethTuple)));
    item(index, 6)->setText(tr("%1").arg(std::get<1>(ethTuple)));
    item(index, 7)->setText(tr("%1").arg(std::get<0>(ipTuple)));
    item(index, 8)->setText(tr("%1").arg(std::get<1>(ipTuple)));
    item(index, 9)->setText(tr("%1").arg(std::get<0>(l4Tuple)));
    item(index, 10)->setText(tr("%1").arg(std::get<1>(l4Tuple)));
    item(index, 11)->setText(tr("%1").arg(QString::fromStdString(thirdLayer ? thirdLayer->toString() : (secondLayer ? secondLayer->toString() : (firstLayer ? firstLayer->toString() : "")))));

    return true;
}
