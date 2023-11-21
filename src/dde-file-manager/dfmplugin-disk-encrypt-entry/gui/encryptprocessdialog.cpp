// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptprocessdialog.h"
#include <QHBoxLayout>
#include <QDateTime>
#include <QRandomGenerator>
#include <QThread>
#include <QCoreApplication>

using namespace dfmplugin_diskenc;

EncryptProcessDialog::EncryptProcessDialog(const QString &title, QWidget *parent)
    : DDialog(parent), title(title)
{
    initUI();
    connect(this, &EncryptProcessDialog::buttonClicked,
            this, &EncryptProcessDialog::onBtnClicked);
}

void EncryptProcessDialog::updateProgress(double progress)
{
    this->progress->setValue(progress * 100);
    if (int(progress) == 1)
        QTimer::singleShot(500, this, [this] { this->close(); });
}

void EncryptProcessDialog::initUI()
{
    clearContents();
    setIcon(QIcon::fromTheme("drive-harddisk-root"));

    QFrame *frame = new QFrame(this);
    QHBoxLayout *lay = new QHBoxLayout(this);
    frame->setLayout(lay);
    addContent(frame);

    progress = new DWaterProgress(this);
    progress->setFixedSize(64, 64);
    progress->setValue(1);
    lay->addWidget(progress);
    progress->start();

    setTitle(title);

    addButton(tr("Cancel"));
}

void EncryptProcessDialog::onBtnClicked(int idx)
{
}
