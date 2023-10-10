// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DECRYPTPARAMSINPUTDIALOG_H
#define DECRYPTPARAMSINPUTDIALOG_H

#include <ddialog.h>
#include <dpasswordedit.h>

namespace dfmplugin_diskenc {

class DecryptParamsInputDialog : public Dtk::Widget::DDialog
{
public:
    explicit DecryptParamsInputDialog(const QString &device, QWidget *parent = nullptr);
    QPair<QString, QString> getInputs();

protected:
    void initUI();

private:
    QString devDesc;
    QString passphrase;

    Dtk::Widget::DPasswordEdit *editor { nullptr };
};

}
#endif   // DECRYPTPARAMSINPUTDIALOG_H
