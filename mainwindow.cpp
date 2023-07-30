#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <exception>
#include <qfiledialog.h>

#include <iostream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , myHexEdit()
    , ui(new Ui::MainWindow)
    , ppp(nullptr)
{
    ui->setupUi(this);
    ui->gridLayout->addWidget(&myHexEdit.editor);

    const auto& enableMenuButtons = [](MainWindow *mainwindow, bool enable) {
        mainwindow->ui->actionSave->setEnabled(enable);
    };
    const auto& enableHexEditButtons = [](MainWindow *mainwindow, bool enable) {
        mainwindow->myHexEdit.prependBytes.setEnabled(enable);
        mainwindow->myHexEdit.appendBytes.setEnabled(enable);
        mainwindow->myHexEdit.deleteBytes.setEnabled(enable);
        mainwindow->myHexEdit.deleteSelection.setEnabled(enable);
    };
    enableMenuButtons(this, false);
    enableHexEditButtons(this, false);

    myHexEdit.editor.setContextMenuPolicy(Qt::CustomContextMenu);
    myHexEdit.prependBytes.setText("Prepend byte(s)..");
    myHexEdit.appendBytes.setText("Append byte(s)..");
    myHexEdit.deleteBytes.setText("Delete byte(s)..");
    myHexEdit.deleteSelection.setText("Delete Selection");
    myHexEdit.contextMenu.addAction(&myHexEdit.prependBytes);
    myHexEdit.contextMenu.addAction(&myHexEdit.appendBytes);
    myHexEdit.contextMenu.addAction(&myHexEdit.deleteBytes);
    myHexEdit.contextMenu.addAction(&myHexEdit.deleteSelection);

    connect(&myHexEdit.bytewindow, &QDialog::finished, this, [&](int result) {
        if (result == 0)
            return;

        const auto option = myHexEdit.bytewindow.getOption();
        const auto offset = myHexEdit.bytewindow.getOffset();
        const auto size = myHexEdit.bytewindow.getSize();
        const auto rawPacket = currentSelectedPacket();
        if (!rawPacket)
            return;

        switch (option) {
        case ByteWindowOption::BWO_UNKNOWN:
        case ByteWindowOption::BWO_INSERT: {
            uint8_t *new_bytes = new uint8_t[size];
            if (!new_bytes)
                break;
            memset(new_bytes, 0, size);
            rawPacket->reallocateData(rawPacket->getRawDataLen() + size);
            rawPacket->insertData(offset, new_bytes, size);
            myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket->getRawData()), rawPacket->getRawDataLen()));
            delete[] new_bytes;
            break;
        }
        case ByteWindowOption::BWO_DELETE:
            rawPacket->removeData(offset, size);
            myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket->getRawData()), rawPacket->getRawDataLen()));
            break;
        }
    });

    connect(&myHexEdit.editor, &QAbstractScrollArea::customContextMenuRequested, this, [&](const QPoint& pos){
        myHexEdit.deleteSelection.setEnabled(myHexEdit.editor.selectedData().size() != 0);

        auto globalPos = myHexEdit.editor.mapToGlobal(pos);
        auto selectedItem = myHexEdit.contextMenu.exec(globalPos);
        const auto cursorPos = myHexEdit.editor.cursorPosition() / 2;
        const auto& selectedLength = myHexEdit.editor.getSelectionEnd() - myHexEdit.editor.getSelectionBegin();
        const auto& showByteWindow = [&](const ByteWindowOption& opt, int offset) {
          myHexEdit.bytewindow.set(opt, offset, selectedLength > 0 ? selectedLength : 1);
          myHexEdit.bytewindow.show();
        };

        if (selectedItem == &myHexEdit.prependBytes) {
            showByteWindow(ByteWindowOption::BWO_INSERT, cursorPos);
        } else if (selectedItem == &myHexEdit.appendBytes) {
            showByteWindow(ByteWindowOption::BWO_INSERT, cursorPos + 1);
        } else if (selectedItem == &myHexEdit.deleteBytes) {
            showByteWindow(ByteWindowOption::BWO_DELETE, cursorPos);
        } else if (selectedItem == &myHexEdit.deleteSelection) {
            const auto rawPacket = currentSelectedPacket();
            if (!rawPacket)
                return;
            if (selectedLength == rawPacket->getRawDataLen())
                return;

            rawPacket->removeData(myHexEdit.editor.getSelectionBegin(), selectedLength);
            myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket->getRawData()), rawPacket->getRawDataLen()));
        } else if (selectedItem) {
            throw std::runtime_error("Unknown context menu " + selectedItem->text().toStdString());
        }
    });

    connect(ui->actionOpen, &QAction::triggered, this, [&](bool){
        QString fileName = QFileDialog::getOpenFileName(this, tr("Open PCAP File"), "", tr("PCAP Files (*.pcap)"));
        if (fileName.length() > 0) {
            if (ppp) {
                delete ppp;
                ppp = nullptr;
            }
            ui->lineEdit->clear();
            ui->tableWidget->clear();
            ui->tableWidget->setRowCount(0);
            myHexEdit.editor.data().clear();
            enableMenuButtons(this, true);
            enableHexEditButtons(this, false);
            ppp = new PcapPlusPlus(fileName.toStdString());
            if (ppp) emit processPcap();
        }
    });

    connect(ui->lineEdit, &QLineEdit::returnPressed, this, [&](){
        if (ppp) {
            if (!ppp->setFilter(ui->lineEdit->text()))
                ui->lineEdit->setStyleSheet("QLineEdit { background: rgb(255, 0, 0); }");
            else {
                ui->lineEdit->setStyleSheet("QLineEdit { background: rgb(255, 255, 255); }");
                ppp->closePcap();
                if (!ppp->openPcap())
                    throw std::runtime_error("Reopen PCAP File to apply a BPF failed.");
                if (!ppp->setFilter(ui->lineEdit->text()))
                    throw std::runtime_error("Could not re-apply a previously set filter.");
                ui->tableWidget->clear();
                ui->tableWidget->setRowCount(0);
                emit processPcap();
            }
        }
    });

    connect(ui->actionSave, &QAction::triggered, this, [&](bool){
        if (ppp) {
            QString selectedFilter;
            QString fileName = QFileDialog::getSaveFileName(this, tr("Save PCAP File"), "", tr("PCAP Files (*.pcap)"), &selectedFilter);
            if (fileName.length() > 0) {
                pcpp::PcapFileWriterDevice pcapWriter(fileName.toStdString() + ".pcap", ppp->getLinkLayer());
                if (!pcapWriter.open())
                    throw std::runtime_error("Could not open file " + fileName.toStdString() + " for writing.");
                {
                    for (auto rawPacket = ppp->rawPacketsBegin(); rawPacket < ppp->rawPacketsEnd(); rawPacket++) {
                        pcapWriter.writePacket(*rawPacket);
                    }
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
        pcpp::PcapFileReaderDevice::PcapStats stats;
        if (ppp->getPcapStatistics(stats))
            ui->statusbar->showMessage("PCAP loaded. Packets: " + QString::fromStdString(std::to_string(stats.packetsRecv))
                                       + ", Dropped: " + QString::fromStdString(std::to_string(stats.packetsDrop)));
        else
            ui->statusbar->showMessage("No PCAP statistics available.");
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
        if (selected.empty())
            return;

        const auto &rawPacket = ppp->getRawPacket(selected.last()->row());
        myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket.getRawData()), rawPacket.getRawDataLen()));
    });

    connect(ui->tableWidget, &QTableWidget::itemSelectionChanged, this, [&]() {
        enableHexEditButtons(this, ui->tableWidget->selectedItems().size() > 0);
        if (ui->tableWidget->selectedItems().size() == 0 && myHexEdit.editor.data().size() > 0)
            myHexEdit.editor.setData(QByteArray());
    });

    connect(&myHexEdit.editor, &QHexEdit::dataChanged, this, [&] {
        const auto rawPacket = currentSelectedPacket();
        if (!rawPacket)
            return;
        const auto& cursorPos = myHexEdit.editor.cursorPosition() / 2;
        auto cursorData = myHexEdit.editor.dataAt(cursorPos, 1);
        if (myHexEdit.editor.cursorPosition() % 2 != 0 && myHexEdit.editor.cursorPosition() / 2 == myHexEdit.editor.data().size() - 1) {
            const uint8_t new_byte = 0x00;
            rawPacket->reallocateData(rawPacket->getRawDataLen() + 1);
            rawPacket->insertData(rawPacket->getRawDataLen(), &new_byte, sizeof(new_byte));
            myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket->getRawData()), rawPacket->getRawDataLen()));
            myHexEdit.editor.setCursorPosition(cursorPos * 2 + 1);
        }
        rawPacket->removeData(cursorPos, 1);
        rawPacket->insertData(cursorPos, reinterpret_cast<const uint8_t *>(cursorData.data()), cursorData.size());
    });
}

MainWindow::~MainWindow()
{
    delete ui;
    delete ppp;
}

pcpp::RawPacket* MainWindow::currentSelectedPacket()
{
    const auto &selected = ui->tableWidget->selectedItems();
    if (!ppp || selected.empty())
        return nullptr;

    return &ppp->getRawPacket(selected.last()->row());
}
