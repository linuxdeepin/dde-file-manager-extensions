// SPDX-FileCopyrightText: 2020 - 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "acquirepindialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QAbstractButton>
#include <DPasswordEdit>

using namespace dfmplugin_diskenc;
DWIDGET_USE_NAMESPACE

AcquirePinDialog::AcquirePinDialog(const QString &tipMessage, QWidget *parent)
    : DDialog(parent),
      descriptionMessage(tipMessage)
{
    setModal(true);
    initUI();
    initConnect();
}

AcquirePinDialog::~AcquirePinDialog()
{
}

void AcquirePinDialog::initUI()
{
    QStringList buttonTexts;
    buttonTexts << tr("Cancel", "button") << tr("Unlock", "button");

    QFrame *content = new QFrame;

    titleLabel = new QLabel(tr("Input password to decrypt the disk"));
    QFont titlefont;
    titlefont.setPointSize(10);
    titleLabel->setFont(titlefont);
    descriptionLabel = new QLabel(descriptionMessage);
    QFont tipfont;
    tipfont.setPointSize(8);
    descriptionLabel->setFont(tipfont);

    passwordLineEdit = new DPasswordEdit;

    QVBoxLayout *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(titleLabel);
    mainLayout->addWidget(descriptionLabel);
    mainLayout->addSpacing(10);
    mainLayout->addWidget(passwordLineEdit);
    mainLayout->addSpacing(10);

    content->setLayout(mainLayout);

    addContent(content);
    addButtons(buttonTexts);
    auto unlockBtn = getButton(1);
    if (unlockBtn)
        unlockBtn->setEnabled(false);
    setSpacing(10);
    setDefaultButton(1);
    setIcon(QIcon::fromTheme("dialog-warning"));
}

void AcquirePinDialog::initConnect()
{
    connect(this, &DDialog::buttonClicked, this, &AcquirePinDialog::handleButtonClicked);
    connect(passwordLineEdit, &DPasswordEdit::textChanged, this, [this](const QString &txt) {
        auto unlockBtn = getButton(1);
        if (unlockBtn)
            unlockBtn->setEnabled(txt.length() != 0);
    });
}

void AcquirePinDialog::handleButtonClicked(int index, QString text)
{
    Q_UNUSED(text)
    if (index == 1) {
        password = passwordLineEdit->text();
    }
    accept();
}

void AcquirePinDialog::showEvent(QShowEvent *event)
{
    passwordLineEdit->setFocus();
    DDialog::showEvent(event);
}

QString AcquirePinDialog::getUerInputedPassword() const
{
    return password;
}
