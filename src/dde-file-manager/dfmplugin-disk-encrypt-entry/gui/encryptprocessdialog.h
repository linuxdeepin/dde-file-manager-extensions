// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTPROCESSDIALOG_H
#define ENCRYPTPROCESSDIALOG_H

#include <DDialog>
#include <DProgressBar>
#include <DWaterProgress>
#include <QTimer>

DWIDGET_USE_NAMESPACE

namespace dfmplugin_diskenc {

class EncryptProcessDialog : public DDialog
{
    Q_OBJECT
public:
    explicit EncryptProcessDialog(const QString &dev, QWidget *parent = nullptr);

    void startEncrypt();
    void encryptDone();

protected:
    void initUI();

private:
    QTimer *timer { nullptr };
    DWaterProgress *progress { nullptr };

    QString devDesc;
};
}

#endif   // ENCRYPTPROCESSDIALOG_H
