#include <exception>
#include <qfiledialog.h>
#include <QMouseEvent>

#include "mainwindow.h"
#include "ui_mainwindow.h"

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

    connect(&tableContextMenu.randomize, &QAction::triggered, this, [this](bool checked __attribute__((unused))){
        ui->tableWidget->randomizeLayerItem(ppp);

        const auto &rawPacket = ppp->getRawPacket(ui->tableWidget->currentRow());
        myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket.getRawData()), rawPacket.getRawDataLen()));
    });

    connect(ui->tableWidget, &QTableWidget::itemChanged, this, [this](QTableWidgetItem *item) {
        ui->tableWidget->setLayerItem(item, ppp, isProcessing);

        if (!isProcessing) {
            const auto &rawPacket = ppp->getRawPacket(item->row());
            myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket.getRawData()), rawPacket.getRawDataLen()));
        }
    });

    connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, [this, enableTableButtons](const QPoint& pos){
        const auto & globalPos = ui->tableWidget->viewport()->mapToGlobal(pos);
        const auto & col = ui->tableWidget->currentColumn() + 1;
        const auto & table = ui->tableWidget;

        if (ppp
            && (table->isEthernetSrcColumn(col) || table->isEthernetDstColumn(col)
                || table->isIpSrcColumn(col) || table->isIpDstColumn(col)
                || table->isPortSrcColumn(col) || table->isPortDstColumn(col)))
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
            ui->tableWidget->clearContents();
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
                ui->tableWidget->clearContents();
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

        isProcessing = true;
        const QDateTime startTime = QDateTime::currentDateTime();
        while (ppp->processPacket(packet)) {
            if (isAboutToClose)
                break;

            emit onPacketAvailable();

            const QDateTime currentTime = QDateTime::currentDateTime();
            if (startTime.msecsTo(currentTime) % 100 == 0)
                qApp->processEvents();
        }
        ui->tableWidget->clearSelection();
        isProcessing = false;

        pcpp::PcapFileReaderDevice::PcapStats stats;
        if (ppp->getPcapStatistics(stats))
            updateStatusBarMessage("PCAP loaded. Packets: " + QString::fromStdString(std::to_string(stats.packetsRecv))
                                   + ", Dropped: " + QString::fromStdString(std::to_string(stats.packetsDrop)));
        else
            updateStatusBarMessage("No PCAP statistics available.");
    });

    connect(this, &MainWindow::onPacketAvailable, this, [&]() {
        emit ui->tableWidget->addRow(ppp);
    });

    connect(ui->tableWidget, &QTableWidget::currentCellChanged, this, [&](int currentRow, int currentColumn, int previousRow, int previousColumn) {
        if (!isProcessing && currentRow >= 0) {
            const auto &rawPacket = ppp->getRawPacket(currentRow);
            myHexEdit.editor.setData(QByteArray::fromRawData(reinterpret_cast<const char *>(rawPacket.getRawData()), rawPacket.getRawDataLen()));
        }
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

void MainWindow::closeEvent(QCloseEvent *closeEvent)
{
    isAboutToClose = true;
    closeEvent->accept();
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
