#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "bytewindow.h"
#include "pcapplusplus.h"
#include "qhexedit2/src/qhexedit.h"

#include <atomic>
#include <optional>
#include <QMainWindow>
#include <QMenu>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    pcpp::RawPacket* currentSelectedPacket();
    bool addTableRow();
    bool updateTableRow(size_t index);

private:
    bool eventFilter(QObject *obj, QEvent *event);
    void updateStatusBarMessage(const QString & message);

    struct {
        QMenu menu;
        QAction randomize;
    } tableContextMenu;

    struct {
        QMenu contextMenu;
        QAction prependBytes;
        QAction appendBytes;
        QAction deleteBytes;
        QAction deleteSelection;
        QHexEdit editor;
        ByteWindow *bytewindow = nullptr;
    } myHexEdit;

    struct {
        int x;
        int y;
    } mouse;

    time_t firstPacketTs = 0;
    Ui::MainWindow *ui = nullptr;
    QString statusbarMessage;
    PcapPlusPlus *ppp = nullptr;
    std::atomic<bool> isProcessing = false;

signals:
    void processPcap();
    void onPacketAvailable();
};
#endif // MAINWINDOW_H
