// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef CHGPASSPHRASEDIALOG_H
#define CHGPASSPHRASEDIALOG_H

#include <ddialog.h>
#include <dpasswordedit.h>

namespace dfmplugin_diskenc {

class ChgPassphraseDialog : public Dtk::Widget::DDialog
{
    Q_OBJECT
public:
    explicit ChgPassphraseDialog(const QString &device, QWidget *parent = nullptr);
    QPair<QString, QString> getPassphrase();

protected:
    void initUI();
    bool validatePasswd();

protected Q_SLOTS:
    void onButtonClicked(int idx);

private:
    QString device;
    Dtk::Widget::DPasswordEdit *oldPass { nullptr };
    Dtk::Widget::DPasswordEdit *newPass1 { nullptr };
    Dtk::Widget::DPasswordEdit *newPass2 { nullptr };
};

}
#endif   // CHGPASSPHRASEDIALOG_H
