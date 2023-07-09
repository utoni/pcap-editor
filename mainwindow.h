#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "pcapplusplus.h"
#include "qhexedit2/src/qhexedit.h"

#include <QMainWindow>

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
    QHexEdit myHexEdit;
    time_t firstPacketTs;
    Ui::MainWindow *ui;
    PcapPlusPlus *ppp;

signals:
    void processPcap();
    void onPacketAvailable(const pcpp::Packet& packet);
};
#endif // MAINWINDOW_H
