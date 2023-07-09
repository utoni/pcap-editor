#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <exception>
#include <qfiledialog.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , myHexEdit()
    , ui(new Ui::MainWindow)
    , ppp(nullptr)
{
    ui->setupUi(this);
    ui->gridLayout->addWidget(&myHexEdit);

    connect(ui->actionOpen, &QAction::triggered, this, [&](bool){
        QString fileName = QFileDialog::getOpenFileName(this, tr("Open PCAP File"), "", tr("PCAP Files (*.pcap)"));
        if (fileName.length() > 0) {
            if (ppp) {
                delete ppp;
                ppp = nullptr;
            }
            ppp = new PcapPlusPlus(fileName.toStdString());
            if (ppp) emit processPcap();
        }
    });

    connect(ui->actionSave, &QAction::triggered, this, [&](bool){
        QString fileName = QFileDialog::getSaveFileName(this, tr("Save PCAP File"), "", tr("PCAP Files (*.pcap)"));
        if (fileName.length() > 0) {
            pcpp::PcapFileWriterDevice pcapWriter(fileName.toStdString(), pcpp::LINKTYPE_ETHERNET);
            if (!pcapWriter.open())
                throw std::runtime_error("Could not open file " + fileName.toStdString() + " for writing.");
            {
                for (auto rawPacket = ppp->rawPacketsBegin(); rawPacket < ppp->rawPacketsEnd(); rawPacket++) {
                    pcapWriter.writePacket(*rawPacket);
                }
            }
        }
    });

    connect(this, &MainWindow::processPcap, this, [&](){
        pcpp::Packet packet;
        if (!ppp) throw std::runtime_error("PcapPlusPlus was not initialized.");
        firstPacketTs = 0;
        while (ppp->processPacket(packet)) {
            if (!firstPacketTs)
                firstPacketTs = packet.getRawPacket()->getPacketTimeStamp().tv_sec;
            emit onPacketAvailable(packet);
        }
    });

    connect(this, &MainWindow::onPacketAvailable, this, [&](const pcpp::Packet& packet) {
        ui->tableWidget->insertRow(ui->tableWidget->rowCount());

        QTableWidgetItem* itemRelativeTime =new QTableWidgetItem(tr("%1").arg(packet.getRawPacket()->getPacketTimeStamp().tv_sec - firstPacketTs));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 0, itemRelativeTime);

        QTableWidgetItem* itemFrameLength = new QTableWidgetItem(tr("%1").arg(packet.getRawPacket()->getFrameLength()));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 1, itemFrameLength);

        const auto *firstLayer = PcapPlusPlus::getFirstLayer(packet);

        QTableWidgetItem* itemFirstLayerProtocol = new QTableWidgetItem(tr("%1").arg(firstLayer ? PcapPlusPlus::getProtocolTypeAsString(firstLayer->getProtocol()) : ""));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 2, itemFirstLayerProtocol);

        const auto *secondLayer = firstLayer ? firstLayer->getNextLayer() : nullptr;

        QTableWidgetItem* itemSecondLayerProtocol = new QTableWidgetItem(tr("%1").arg(secondLayer ? PcapPlusPlus::getProtocolTypeAsString(secondLayer->getProtocol()) : ""));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 3, itemSecondLayerProtocol);

        const auto *thirdLayer = secondLayer ? secondLayer->getNextLayer() : nullptr;

        QTableWidgetItem* itemThirdLayerProtocol = new QTableWidgetItem(tr("%1").arg(thirdLayer ? PcapPlusPlus::getProtocolTypeAsString(thirdLayer->getProtocol()) : ""));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 4, itemThirdLayerProtocol);

        const auto ethTuple = PcapPlusPlus::getEthTuple(packet);

        QTableWidgetItem* itemSrcMac = new QTableWidgetItem(tr("%1").arg(std::get<0>(ethTuple)));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 5, itemSrcMac);

        QTableWidgetItem* itemDstMac = new QTableWidgetItem(tr("%1").arg(std::get<1>(ethTuple)));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 6, itemDstMac);

        const auto ipTuple = PcapPlusPlus::getIpTuple(packet);

        QTableWidgetItem* itemSrcIp = new QTableWidgetItem(tr("%1").arg(std::get<0>(ipTuple)));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 7, itemSrcIp);

        QTableWidgetItem* itemDstIp = new QTableWidgetItem(tr("%1").arg(std::get<1>(ipTuple)));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 8, itemDstIp);

        const auto l4Tuple = PcapPlusPlus::getLayer4Tuple(packet);

        QTableWidgetItem* itemSrcPort = new QTableWidgetItem(tr("%1").arg(std::get<0>(l4Tuple)));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 9, itemSrcPort);

        QTableWidgetItem* itemDstPort = new QTableWidgetItem(tr("%1").arg(std::get<1>(l4Tuple)));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 10, itemDstPort);

        QTableWidgetItem* itemDesc = new QTableWidgetItem(tr("%1").arg(QString::fromStdString(thirdLayer ? thirdLayer->toString() : (secondLayer ? secondLayer->toString() : (firstLayer ? firstLayer->toString() : "")))));
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 11, itemDesc);
    });

    connect(ui->tableWidget, &QTableWidget::cellPressed, this, [&] {
        const auto &selected = ui->tableWidget->selectedItems();
        const auto &rawPacket = ppp->getRawPacket(selected.last()->row());
        myHexEdit.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket.getRawData()), rawPacket.getRawDataLen()));
    });

    connect(&myHexEdit, &QHexEdit::dataChanged, this, [&] {
        const auto &selected = ui->tableWidget->selectedItems();
        auto &rawPacket = ppp->getRawPacket(selected.last()->row());
        const auto cursorPos = myHexEdit.cursorPosition() / 2;
        const auto cursorData = myHexEdit.dataAt(cursorPos, 1);
        rawPacket.removeData(cursorPos, 1);
        rawPacket.insertData(cursorPos, reinterpret_cast<const uint8_t *>(cursorData.data()), cursorData.size());
    });
}

MainWindow::~MainWindow()
{
    delete ui;
    delete ppp;
}
