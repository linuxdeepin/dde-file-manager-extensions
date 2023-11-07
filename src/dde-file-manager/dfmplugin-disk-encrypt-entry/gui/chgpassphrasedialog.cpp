// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "chgpassphrasedialog.h"

#include <QFormLayout>
#include <QLabel>
#include <QRegularExpression>
#include <QToolTip>

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
    setTitle(tr("Change passphrase for %1").arg(device));
    QFrame *content = new QFrame(this);
    QFormLayout *lay = new QFormLayout(content);

    oldPass = new Dtk::Widget::DPasswordEdit(this);
    newPass1 = new Dtk::Widget::DPasswordEdit(this);
    newPass2 = new Dtk::Widget::DPasswordEdit(this);

    lay->addRow(tr("Old passphrase"), oldPass);
    lay->addRow(tr("New passphrase"), newPass1);
    lay->addRow(tr("Repeat new"), newPass2);

    addContent(content);
    addButton(tr("Cancel"));
    addButton(tr("Confirm"));

    setOnButtonClickedClose(false);
}

bool ChgPassphraseDialog::validatePasswd()
{
    auto showText = [this](const QString &t, const QPoint &p) {
        QToolTip::showText(getContent(0)->mapToGlobal(p), t, this);
    };

    auto nonEmpty = [=](Dtk::Widget::DPasswordEdit *editor) {
        QString pwd = editor->text().trimmed();
        if (pwd.isEmpty()) {
            showText(tr("Empty"), editor->pos());
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
        showText(tr("Not safe"), newPass1->pos());
        return false;
    }

    if (pwd1 != pwd2) {
        showText(tr("Not equal"), newPass2->pos());
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
