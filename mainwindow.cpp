#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <exception>
#include <qfiledialog.h>
#include <QMouseEvent>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , tableContextMenu()
    , myHexEdit()
    , ui(new Ui::MainWindow)
    , statusbarMessage()
{
    if (!ui)
        throw std::runtime_error("UI - MainWindow: not enough memory available");

    ui->setupUi(this);
    ui->gridLayout->addWidget(&myHexEdit.editor);
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableWidget->setMouseTracking(true);
    qApp->installEventFilter(this);

    myHexEdit.bytewindow = new ByteWindow(parent);
    if (!myHexEdit.bytewindow)
        throw std::runtime_error("UI - ByteWindow: not enough memory available");

    const auto& enableTableButtons = [](MainWindow *mainwindow, bool enable) {
        mainwindow->tableContextMenu.randomize.setEnabled(enable);
    };
    const auto& enableMenuButtons = [](MainWindow *mainwindow, bool enable) {
        mainwindow->ui->actionSave->setEnabled(enable);
        mainwindow->ui->actionSave_Selection->setEnabled(enable);
    };
    const auto& enableHexEditButtons = [](MainWindow *mainwindow, bool enable) {
        mainwindow->myHexEdit.prependBytes.setEnabled(enable);
        mainwindow->myHexEdit.appendBytes.setEnabled(enable);
        mainwindow->myHexEdit.deleteBytes.setEnabled(enable);
        mainwindow->myHexEdit.deleteSelection.setEnabled(enable);
    };
    enableTableButtons(this, false);
    enableMenuButtons(this, false);
    enableHexEditButtons(this, false);

    const auto& isEthernetSrcColumn = [this](const int& column) {
        return column == 6;
    };
    const auto& isEthernetDstColumn = [this](const int& column) {
        return column == 7;
    };
    const auto& isIpSrcColumn = [this](const int& column) {
        return column == 8;
    };
    const auto& isIpDstColumn = [this](const int& column) {
        return column == 9;
    };
    const auto& isPortSrcColumn = [this](const int& column) {
        return column == 10;
    };
    const auto& isPortDstColumn = [this](const int& column) {
        return column == 11;
    };

    tableContextMenu.randomize.setText("Randomize");
    tableContextMenu.menu.addAction(&tableContextMenu.randomize);

    myHexEdit.editor.setContextMenuPolicy(Qt::CustomContextMenu);
    myHexEdit.prependBytes.setText("Prepend byte(s)..");
    myHexEdit.appendBytes.setText("Append byte(s)..");
    myHexEdit.deleteBytes.setText("Delete byte(s)..");
    myHexEdit.deleteSelection.setText("Delete Selection");
    myHexEdit.contextMenu.addAction(&myHexEdit.prependBytes);
    myHexEdit.contextMenu.addAction(&myHexEdit.appendBytes);
    myHexEdit.contextMenu.addAction(&myHexEdit.deleteBytes);
    myHexEdit.contextMenu.addAction(&myHexEdit.deleteSelection);

    connect(&tableContextMenu.randomize, &QAction::triggered, this, [this, isEthernetSrcColumn, isEthernetDstColumn, isIpSrcColumn, isIpDstColumn, isPortSrcColumn, isPortDstColumn](bool checked __attribute__((unused))){
        if (!ppp)
            throw std::runtime_error("Can not randomize, no packets available");

        const auto & y = ui->tableWidget->currentRow();
        const auto & col = ui->tableWidget->currentColumn() + 1;

        if (isEthernetSrcColumn(col) || isEthernetDstColumn(col)) {
            ppp->randomizeEth(y, isEthernetSrcColumn(col));
        } else if (isIpSrcColumn(col) || isIpDstColumn(col)) {
            ppp->randomizeIp(y, isIpSrcColumn(col));
        } else if (isPortSrcColumn(col) || isPortDstColumn(col)) {
            ppp->randomizePort(y, isPortSrcColumn(col));
        } else throw std::runtime_error("BUG: No supported column selected");

        if (!MainWindow::updateTableRow(y))
            throw std::runtime_error("BUG: Could not update table row");
    });

    connect(ui->tableWidget, &QTableWidget::itemChanged, this, [this, isEthernetSrcColumn, isEthernetDstColumn, isIpSrcColumn, isIpDstColumn, isPortSrcColumn, isPortDstColumn](QTableWidgetItem *item) {
        if (!item || !ppp)
            return;

        const auto & y = ui->tableWidget->currentRow();
        const auto & col = ui->tableWidget->currentColumn() + 1;
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
        if (!MainWindow::updateTableRow(y))
            throw std::runtime_error("BUG: Could not update table row");
    });

    connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, [this, enableTableButtons, isEthernetSrcColumn, isEthernetDstColumn, isIpSrcColumn, isIpDstColumn, isPortSrcColumn, isPortDstColumn](const QPoint& pos){
        const auto & globalPos = ui->tableWidget->viewport()->mapToGlobal(pos);
        const auto & col = ui->tableWidget->currentColumn() + 1;

        if (ppp
            && (isEthernetSrcColumn(col) || isEthernetDstColumn(col)
                || isIpSrcColumn(col) || isIpDstColumn(col)
                || isPortSrcColumn(col) || isPortDstColumn(col)))
            enableTableButtons(this, true);
        else
            enableTableButtons(this, false);

        tableContextMenu.menu.popup(globalPos);
    });

    connect(myHexEdit.bytewindow, &QDialog::finished, this, [&](int result) {
        if (result == 0)
            return;

        const auto option = myHexEdit.bytewindow->getOption();
        const auto offset = myHexEdit.bytewindow->getOffset();
        const auto size = myHexEdit.bytewindow->getSize();
        const auto rawPacket = currentSelectedPacket();
        if (!rawPacket)
            return;

        switch (option) {
        case ByteWindowOption::BWO_UNKNOWN:
            throw std::runtime_error("Unknown byte window option");
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

        myHexEdit.editor.setCursorPosition(offset * 2);
    });

    connect(&myHexEdit.editor, &QAbstractScrollArea::customContextMenuRequested, this, [&](const QPoint& pos){
        myHexEdit.deleteSelection.setEnabled(myHexEdit.editor.selectedData().size() != 0);

        auto globalPos = myHexEdit.editor.mapToGlobal(pos);
        auto selectedItem = myHexEdit.contextMenu.exec(globalPos);
        const auto cursorPos = myHexEdit.editor.cursorPosition() / 2;
        const auto& selectionBegin = myHexEdit.editor.getSelectionBegin();
        const auto& selectedLength = myHexEdit.editor.getSelectionEnd() - selectionBegin;
        const auto& showByteWindow = [this, selectedLength](const ByteWindowOption& opt, int offset) {
            myHexEdit.bytewindow->set(opt, offset, selectedLength > 0 ? selectedLength : 1);
            myHexEdit.bytewindow->show();
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
            myHexEdit.editor.setCursorPosition(selectionBegin * 2);
        } else if (selectedItem) {
            throw std::runtime_error("Unknown context menu " + selectedItem->text().toStdString());
        }
    });

    connect(ui->actionOpen, &QAction::triggered, this, [this, enableTableButtons, enableMenuButtons, enableHexEditButtons](bool){
        QString fileName = QFileDialog::getOpenFileName(this, tr("Open PCAP File"), "", tr("PCAP Files (*.pcap);;All Files (*.*)"));
        if (fileName.length() > 0) {
            ui->lineEdit->clear();
            ui->tableWidget->clearSelection();
            ui->tableWidget->clear();
            ui->tableWidget->setRowCount(0);
            myHexEdit.editor.data().data_ptr()->clear();
            enableTableButtons(this, true);
            enableMenuButtons(this, true);
            enableHexEditButtons(this, false);
            ui->actionSave_Selection->setEnabled(false);

            if (ppp) {
                delete ppp;
                ppp = nullptr;
            }
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
        if (!ppp)
            return;

        QString selectedFilter;
        QString fileName = QFileDialog::getSaveFileName(this, tr("Save PCAP File"), "", tr("PCAP Files (*.pcap);;All Files (*.*)"), &selectedFilter);
        if (fileName.length() > 0) {
            pcpp::PcapFileWriterDevice pcapWriter(fileName.toStdString(), ppp->getLinkLayer());
            if (!pcapWriter.open())
                throw std::runtime_error("Could not open file " + fileName.toStdString() + " for writing.");
            {
                for (auto rawPacket = ppp->rawPacketsBegin(); rawPacket < ppp->rawPacketsEnd(); rawPacket++) {
                    pcapWriter.writePacket(*rawPacket);
                }
                pcapWriter.flush();
                pcapWriter.close();
            }
        }
    });

    connect(ui->actionSave_Selection, &QAction::triggered, this, [&](bool){
        if (!ppp)
            return;

        QString selectedFilter;
        QString fileName = QFileDialog::getSaveFileName(this, tr("Save PCAP File"), "", tr("PCAP Files (*.pcap);;All Files (*.*)"), &selectedFilter);
        if (fileName.length() > 0) {
            pcpp::PcapFileWriterDevice pcapWriter(fileName.toStdString(), ppp->getLinkLayer());
            if (!pcapWriter.open())
                throw std::runtime_error("Could not open file " + fileName.toStdString() + " for writing.");
            {
                QList<QTableWidgetSelectionRange> selection(ui->tableWidget->selectedRanges());
                std::sort(selection.begin(), selection.end(), [](const QTableWidgetSelectionRange & a, const QTableWidgetSelectionRange & b){
                    return a.topRow() < b.topRow();
                });
                for (const auto & selected : selection) {
                    pcapWriter.writePacket(ppp->getRawPacket(selected.topRow()));
                }
                pcapWriter.flush();
                pcapWriter.close();
            }
        }
    });

    connect(this, &MainWindow::processPcap, this, [&](){
        pcpp::Packet packet;
        if (!ppp) throw std::runtime_error("PcapPlusPlus was not initialized.");
        firstPacketTs = 0;

        isProcessing = true;
        while (ppp->processPacket(packet)) {
            if (!firstPacketTs)
                firstPacketTs = packet.getRawPacket()->getPacketTimeStamp().tv_sec;
            emit onPacketAvailable();
        }
        isProcessing = false;

        pcpp::PcapFileReaderDevice::PcapStats stats;
        if (ppp->getPcapStatistics(stats))
            updateStatusBarMessage("PCAP loaded. Packets: " + QString::fromStdString(std::to_string(stats.packetsRecv))
                                   + ", Dropped: " + QString::fromStdString(std::to_string(stats.packetsDrop)));
        else
            updateStatusBarMessage("No PCAP statistics available.");
    });

    connect(this, &MainWindow::onPacketAvailable, this, [&]() {
        if (!addTableRow())
            throw std::runtime_error("Could not add row to table for packet");
    });

    connect(ui->tableWidget, &QTableWidget::cellPressed, this, [&] {
        const auto &selected = ui->tableWidget->selectedItems();
        if (selected.empty())
            return;

        const auto &rawPacket = ppp->getRawPacket(selected.last()->row());
        myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket.getRawData()), rawPacket.getRawDataLen()));
    });

    connect(ui->tableWidget, &QTableWidget::itemSelectionChanged, this, [this, enableHexEditButtons]() {
        enableHexEditButtons(this, ui->tableWidget->selectedItems().size() > 0);
        ui->actionSave_Selection->setEnabled(ui->tableWidget->selectedItems().size() > 0);
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
    ui = nullptr;

    delete myHexEdit.bytewindow;
    myHexEdit.bytewindow = nullptr;

    delete ppp;
    ppp = nullptr;
}

pcpp::RawPacket* MainWindow::currentSelectedPacket()
{
    const auto &selected = ui->tableWidget->selectedItems();
    if (!ppp || selected.empty())
        return nullptr;

    return &ppp->getRawPacket(selected.last()->row());
}

bool MainWindow::addTableRow()
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

    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 0, itemRelativeTime);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 1, itemFrameLength);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 2, itemFirstLayerProtocol);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 3, itemSecondLayerProtocol);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 4, itemThirdLayerProtocol);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 5, itemSrcMac);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 6, itemDstMac);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 7, itemSrcIp);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 8, itemDstIp);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 9, itemSrcPort);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 10, itemDstPort);
    ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 11, itemDesc);

    ui->tableWidget->item(ui->tableWidget->rowCount() - 1, 0)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    ui->tableWidget->item(ui->tableWidget->rowCount() - 1, 1)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    ui->tableWidget->item(ui->tableWidget->rowCount() - 1, 2)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    ui->tableWidget->item(ui->tableWidget->rowCount() - 1, 3)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    ui->tableWidget->item(ui->tableWidget->rowCount() - 1, 4)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);
    ui->tableWidget->item(ui->tableWidget->rowCount() - 1, 11)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemNeverHasChildren);

    return updateTableRow(ui->tableWidget->rowCount() - 1);
}

bool MainWindow::updateTableRow(size_t index)
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

    ui->tableWidget->item(index, 0)->setText(tr("%1").arg(parsedPacket.getRawPacket()->getPacketTimeStamp().tv_sec - firstPacketTs));
    ui->tableWidget->item(index, 1)->setText(tr("%1").arg(parsedPacket.getRawPacket()->getFrameLength()));
    ui->tableWidget->item(index, 2)->setText(tr("%1").arg(firstLayer ? PcapPlusPlus::getProtocolTypeAsString(firstLayer->getProtocol()) : ""));
    ui->tableWidget->item(index, 3)->setText(tr("%1").arg(secondLayer ? PcapPlusPlus::getProtocolTypeAsString(secondLayer->getProtocol()) : ""));
    ui->tableWidget->item(index, 4)->setText(tr("%1").arg(thirdLayer ? PcapPlusPlus::getProtocolTypeAsString(thirdLayer->getProtocol()) : ""));
    ui->tableWidget->item(index, 5)->setText(tr("%1").arg(std::get<0>(ethTuple)));
    ui->tableWidget->item(index, 6)->setText(tr("%1").arg(std::get<1>(ethTuple)));
    ui->tableWidget->item(index, 7)->setText(tr("%1").arg(std::get<0>(ipTuple)));
    ui->tableWidget->item(index, 8)->setText(tr("%1").arg(std::get<1>(ipTuple)));
    ui->tableWidget->item(index, 9)->setText(tr("%1").arg(std::get<0>(l4Tuple)));
    ui->tableWidget->item(index, 10)->setText(tr("%1").arg(std::get<1>(l4Tuple)));
    ui->tableWidget->item(index, 11)->setText(tr("%1").arg(QString::fromStdString(thirdLayer ? thirdLayer->toString() : (secondLayer ? secondLayer->toString() : (firstLayer ? firstLayer->toString() : "")))));

    return true;
}

bool MainWindow::eventFilter(QObject *obj __attribute__((unused)), QEvent *event)
{
    if (event->type() == QEvent::MouseMove)
    {
        QMouseEvent *mouseEvent = static_cast<QMouseEvent*>(event);

        mouse.x = mouseEvent->pos().x();
        mouse.y = mouseEvent->pos().y();
        ui->statusbar->showMessage(tr("[x: %1 | y: %2] %3").arg(mouse.x, 4).arg(mouse.y, 4).arg(statusbarMessage));
    }
    return false;
}

void MainWindow::updateStatusBarMessage(const QString & message) {
    statusbarMessage = message;
    ui->statusbar->showMessage(tr("[x: %1 | y: %2] %3").arg(mouse.x, 4).arg(mouse.y, 4).arg(message));
}
