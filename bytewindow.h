#ifndef BYTEWINDOW_H
#define BYTEWINDOW_H

#include <QDialog>

QT_BEGIN_NAMESPACE
namespace Ui { class ByteWindow; }
QT_END_NAMESPACE

enum class ByteWindowOption {
    BWO_UNKNOWN,
    BWO_INSERT,
    BWO_DELETE
};

class ByteWindow : public QDialog
{
    Q_OBJECT

public:
    explicit ByteWindow(QWidget *parent = nullptr);
    ~ByteWindow();
    void set(ByteWindowOption option, int offset, int size);
    ByteWindowOption getOption();
    int getOffset();
    int getSize();

private:
    Ui::ByteWindow *ui;
};
#endif // BYTEWINDOW_H
