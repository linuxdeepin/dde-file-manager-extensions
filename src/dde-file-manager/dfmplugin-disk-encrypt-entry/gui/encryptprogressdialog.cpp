// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptprogressdialog.h"

#include <QCoreApplication>
#include <QVBoxLayout>
#include <QLabel>
#include <QTimer>

using namespace dfmplugin_diskenc;

EncryptProgressDialog::EncryptProgressDialog(QWidget *parent)
    : DDialog(parent)
{
    initUI();
}

void EncryptProgressDialog::setText(const QString &title, const QString &message)
{
    setTitle(title);
    this->message->setText(message);
}

void EncryptProgressDialog::updateProgress(double progress)
{
    this->progress->setValue(progress * 100);
    if (int(progress) == 1)
        QTimer::singleShot(500, this, [this] { this->close(); });
}

void EncryptProgressDialog::initUI()
{
    clearContents();
    setIcon(QIcon::fromTheme("drive-harddisk-root"));
    setFixedWidth(400);

    QFrame *frame = new QFrame(this);
    QVBoxLayout *lay = new QVBoxLayout(this);
    lay->setSpacing(30);
    lay->setContentsMargins(0, 30, 0, 20);
    frame->setLayout(lay);
    addContent(frame);

    progress = new DWaterProgress(this);
    progress->setFixedSize(64, 64);
    progress->setValue(1);
    lay->addWidget(progress, 0, Qt::AlignCenter);
    progress->start();

    message = new QLabel(this);
    lay->addWidget(message, 0, Qt::AlignCenter);

    setCloseButtonVisible(false);
}
