#ifndef PACKETSTABLEWIDGET_H
#define PACKETSTABLEWIDGET_H

#include <QTableWidget>

#include "pcapplusplus.h"

class PacketsTableWidget : public QTableWidget
{
    Q_OBJECT

public:
    PacketsTableWidget(QWidget *parent = nullptr);

    bool isEthernetSrcColumn(const int& column) {
        return column == 6;
    };
    bool isEthernetDstColumn(const int& column) {
        return column == 7;
    };
    bool isIpSrcColumn(const int& column) {
        return column == 8;
    };
    bool isIpDstColumn(const int& column) {
        return column == 9;
    };
    bool isPortSrcColumn(const int& column) {
        return column == 10;
    };
    bool isPortDstColumn(const int& column) {
        return column == 11;
    };

private:
    bool addTableRow(PcapPlusPlus *ppp);
    bool updateTableRow(size_t index, PcapPlusPlus *ppp);

signals:
    bool addRow(PcapPlusPlus *ppp);
    bool updateRow(size_t index, PcapPlusPlus *ppp);

public slots:
    void randomizeLayerItem(PcapPlusPlus *ppp);
    void setLayerItem(QTableWidgetItem *item, PcapPlusPlus *ppp, bool isProcessing);
};

#endif // PACKETSTABLEWIDGET_H
