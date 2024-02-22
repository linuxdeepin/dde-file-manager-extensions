// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptprogressdialog.h"

#include <QCoreApplication>
#include <QVBoxLayout>
#include <QLabel>
#include <QTimer>
#include <QStackedLayout>
#include <QIcon>

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
    mainLay->setCurrentIndex(0);
    this->progress->setValue(progress * 100);
    clearButtons();
    setCloseButtonVisible(false);
}

void EncryptProgressDialog::showResultPage(bool success, const QString &title, const QString &message)
{
    mainLay->setCurrentIndex(1);

    setTitle(title);
    resultMsg->setText(message);
    QIcon icon = success ? QIcon::fromTheme("dialog-ok") : QIcon::fromTheme("dialog-error");
    iconLabel->setPixmap(icon.pixmap(64, 64));

    addButton(tr("Confirm"));
    setCloseButtonVisible(true);
    setAttribute(Qt::WA_DeleteOnClose);
    setOnButtonClickedClose(true);
}

void EncryptProgressDialog::initUI()
{
    clearContents();
    setIcon(QIcon::fromTheme("drive-harddisk-root"));
    setFixedWidth(400);

    QFrame *frame = new QFrame(this);
    mainLay = new QStackedLayout(frame);
    mainLay->setContentsMargins(0, 0, 0, 0);
    mainLay->setSpacing(0);
    addContent(frame);

    QFrame *progressPage = new QFrame(this);
    QVBoxLayout *progressLay = new QVBoxLayout(progressPage);
    progressLay->setSpacing(30);
    progressLay->setContentsMargins(0, 30, 0, 20);

    progress = new DWaterProgress(this);
    progress->setFixedSize(64, 64);
    progress->setValue(1);
    progressLay->addWidget(progress, 0, Qt::AlignCenter);
    progress->start();

    message = new QLabel(this);
    progressLay->addWidget(message, 0, Qt::AlignCenter);

    QFrame *resultPage = new QFrame(this);
    QVBoxLayout *resultLay = new QVBoxLayout(resultPage);
    resultLay->setSpacing(20);
    resultLay->setContentsMargins(0, 30, 0, 0);

    iconLabel = new QLabel(this);
    iconLabel->setFixedSize(64, 64);
    resultLay->addWidget(iconLabel, 0, Qt::AlignCenter);

    resultMsg = new QLabel(this);
    resultLay->addWidget(resultMsg, 0, Qt::AlignCenter);

    mainLay->addWidget(progressPage);
    mainLay->addWidget(resultPage);
}
