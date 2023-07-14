// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTPARAMSINPUTDIALOG_H
#define ENCRYPTPARAMSINPUTDIALOG_H

#include <DDialog>
#include <DPasswordEdit>
#include <DLineEdit>
#include <DFileChooserEdit>

DWIDGET_USE_NAMESPACE

namespace dfmplugin_diskenc {
struct ParamsInputs
{
    QString passwd;
    QString serverAddr;
    QString exportPath;
    QString devDesc;
};

class EncryptParamsInputDialog : public DDialog
{
    Q_OBJECT
public:
    explicit EncryptParamsInputDialog(const QString &dev, QWidget *parent = nullptr);
    ParamsInputs getInputs();

protected:
    void initUi();
    void initConn();

protected Q_SLOTS:
    void onButtonClicked(int idx);

private:
    DPasswordEdit *passwd1 { nullptr };
    DPasswordEdit *passwd2 { nullptr };
    DLineEdit *serverAddr { nullptr };
    DFileChooserEdit *exportPath { nullptr };

    QString device;
};

}
#endif   // ENCRYPTPARAMSINPUTDIALOG_H
