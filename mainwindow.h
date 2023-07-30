#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "bytewindow.h"
#include "pcapplusplus.h"
#include "qhexedit2/src/qhexedit.h"

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

private:
    struct {
        QMenu contextMenu;
        QAction prependBytes;
        QAction appendBytes;
        QAction deleteBytes;
        QAction deleteSelection;
        QHexEdit editor;
        ByteWindow bytewindow;
    } myHexEdit;

    time_t firstPacketTs;
    PcapPlusPlus *ppp;
    Ui::MainWindow *ui;

signals:
    void processPcap();
    void onPacketAvailable(const pcpp::Packet& packet);
};
#endif // MAINWINDOW_H
