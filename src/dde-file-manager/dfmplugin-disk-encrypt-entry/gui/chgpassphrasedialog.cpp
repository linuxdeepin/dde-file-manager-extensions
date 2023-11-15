// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "chgpassphrasedialog.h"
#include "utils/encryptutils.h"

#include <QFormLayout>
#include <QLabel>
#include <QRegularExpression>

using namespace dfmplugin_diskenc;

ChgPassphraseDialog::ChgPassphraseDialog(const QString &device, QWidget *parent)
    : Dtk::Widget::DDialog(parent),
      device(device)
{
    initUI();

    connect(this, &ChgPassphraseDialog::buttonClicked,
            this, &ChgPassphraseDialog::onButtonClicked);
}

QPair<QString, QString> ChgPassphraseDialog::getPassphrase()
{
    return { oldPass->text(), newPass1->text() };
}

void ChgPassphraseDialog::initUI()
{
    int keyType = device_utils::encKeyType(device);
    QString keyTypeStr = tr("passphrase");
    if (keyType == 1)   // PIN
        keyTypeStr = tr("PIN");

    setTitle(tr("Change %1 for %2").arg(keyTypeStr).arg(device));
    QFrame *content = new QFrame(this);
    QFormLayout *lay = new QFormLayout(content);

    oldPass = new Dtk::Widget::DPasswordEdit(this);
    newPass1 = new Dtk::Widget::DPasswordEdit(this);
    newPass2 = new Dtk::Widget::DPasswordEdit(this);

    lay->addRow(tr("Old %1").arg(keyTypeStr), oldPass);
    lay->addRow(tr("New %1").arg(keyTypeStr), newPass1);
    lay->addRow(tr("Repeat %1").arg(keyTypeStr), newPass2);

    addContent(content);
    addButton(tr("Cancel"));
    addButton(tr("Confirm"));

    setOnButtonClickedClose(false);
}

bool ChgPassphraseDialog::validatePasswd()
{
    int keyType = device_utils::encKeyType(device);
    QString keyTypeStr = tr("passphrase");
    if (keyType == 1)   // PIN
        keyTypeStr = tr("PIN");

    auto nonEmpty = [=](Dtk::Widget::DPasswordEdit *editor) {
        QString pwd = editor->text().trimmed();
        if (pwd.isEmpty()) {
            editor->showAlertMessage(tr("%1 cannot be empty").arg(keyTypeStr));
            return false;
        }
        return true;
    };

    if (!(nonEmpty(oldPass)
          && nonEmpty(newPass1)
          && nonEmpty(newPass2)))
        return false;

    QList<QRegularExpression> regx {
        QRegularExpression { R"([A-Z])" },
        QRegularExpression { R"([a-z])" },
        QRegularExpression { R"([0-9])" },
        QRegularExpression { R"([^A-Za-z0-9])" }
    };

    QString pwd1 = newPass1->text().trimmed();
    QString pwd2 = newPass2->text().trimmed();

    int factor = 0;
    std::for_each(regx.cbegin(), regx.cend(), [&factor, pwd1](const QRegularExpression &reg) {
        if (pwd1.contains(reg))
            factor += 1;
    });

    if (factor < 3 || pwd1.length() < 8) {
        newPass1->showAlertMessage(tr("%1 at least 8 bits with A-Z, a-z, 0-9 and symbols").arg(keyTypeStr));
        return false;
    }

    if (pwd1 != pwd2) {
        newPass2->showAlertMessage(tr("%1 inconsistency").arg(keyTypeStr));
        return false;
    }

    return true;
}

void ChgPassphraseDialog::onButtonClicked(int idx)
{
    if (idx == 1) {
        if (!validatePasswd())
            return;
        accept();
    } else {
        reject();
    }
}
