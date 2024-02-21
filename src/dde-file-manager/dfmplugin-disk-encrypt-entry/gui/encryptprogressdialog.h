// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTPROGRESSDIALOG_H
#define ENCRYPTPROGRESSDIALOG_H

#include <DDialog>
#include <DWaterProgress>

DWIDGET_USE_NAMESPACE

    class QStackedLayout;

namespace dfmplugin_diskenc {

class EncryptProgressDialog : public DDialog
{
    Q_OBJECT
public:
    explicit EncryptProgressDialog(QWidget *parent = nullptr);
    void setText(const QString &title, const QString &message);
    void updateProgress(double progress);
    void showResultPage(bool success, const QString &title, const QString &message);

protected:
    void initUI();

private:
    DWaterProgress *progress { nullptr };
    QLabel *message { nullptr };
    QStackedLayout *mainLay { nullptr };
    QLabel *iconLabel { nullptr };
    QLabel *resultMsg { nullptr };
};
}

#endif   // ENCRYPTPROGRESSDIALOG_H
