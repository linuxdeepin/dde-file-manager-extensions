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

EncryptProcessDialog::EncryptProcessDialog(const QString &dev, QWidget *parent)
    : DDialog(parent), devDesc(dev)
{
    initUI();
}

void EncryptProcessDialog::encryptDone()
{
    int currVal = progress->value();
    int delta = 100 - currVal;
    int step = delta / 5 + 1;
    for (int i = 0; i < 5; i++) {
        currVal += step;
        if (currVal > 100)
            currVal = 100;
        progress->setValue(currVal);
        update();
        qApp->processEvents();
        QThread::msleep(500);
    }
    accept();
}

void EncryptProcessDialog::startEncrypt()
{
    timer->start();
    progress->start();
}

void EncryptProcessDialog::initUI()
{
    clearContents();
    QFrame *frame = new QFrame(this);
    QHBoxLayout *lay = new QHBoxLayout(this);
    frame->setLayout(lay);
    addContent(frame);

    progress = new DWaterProgress(this);
    progress->setFixedSize(64, 64);
    progress->setValue(1);
    lay->addWidget(progress);

    setTitle("正在加密" + devDesc);
    setCloseButtonVisible(false);

    timer = new QTimer(this);
    timer->setInterval(500);
    int seed = QDateTime::currentMSecsSinceEpoch();
    QSharedPointer<QRandomGenerator> random(new QRandomGenerator(seed));
    connect(timer, &QTimer::timeout, this, [=] {
        int randVal = random->generate() % 3;
        if (progress->value() < 95)
            progress->setValue(progress->value() + randVal);
        else
            timer->stop();
        update();
    });
}
