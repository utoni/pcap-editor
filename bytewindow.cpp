#include "bytewindow.h"
#include "ui_bytewindow.h"

ByteWindow::ByteWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ByteWindow)
{
    ui->setupUi(this);
}

ByteWindow::~ByteWindow()
{
    delete ui;
}

void ByteWindow::set(ByteWindowOption option, int offset, int size)
{
    switch (option) {
    case ByteWindowOption::BWO_UNKNOWN:
    case ByteWindowOption::BWO_INSERT:
        ui->radioButtonInsert->click();
        break;
    case ByteWindowOption::BWO_DELETE:
        ui->radioButtonDelete->click();
        break;
    }

    ui->spinBoxIndex->setValue(offset);
    ui->spinBoxSize->setValue(size);
}

ByteWindowOption ByteWindow::getOption()
{
    if (ui->radioButtonInsert->isChecked())
        return ByteWindowOption::BWO_INSERT;
    if (ui->radioButtonDelete->isChecked())
        return ByteWindowOption::BWO_DELETE;

    return ByteWindowOption::BWO_UNKNOWN;
}

int ByteWindow::getOffset()
{
    return ui->spinBoxIndex->value();
}

int ByteWindow::getSize()
{
    return ui->spinBoxSize->value();
}
