// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptparamsinputdialog.h"

#include <QVBoxLayout>
#include <QToolTip>
#include <QLabel>

using namespace dfmplugin_diskenc;

EncryptParamsInputDialog::EncryptParamsInputDialog(const QString &dev, QWidget *parent)
    : DDialog(parent), device(dev)
{
    initUi();
    initConn();
}

ParamsInputs EncryptParamsInputDialog::getInputs()
{
    QString dev = device;
    QString keyPath = exportPath->text() + QString("/key_file%1.txt").arg(dev.replace("/", "_"));
    return { passwd1->text(), serverAddr->text(), keyPath, device };
}

void EncryptParamsInputDialog::initUi()
{
    clearContents(true);
    setOnButtonClickedClose(false);

    QFrame *frame = new QFrame(this);
    QVBoxLayout *lay = new QVBoxLayout(frame);
    frame->setLayout(lay);
    addContent(frame);

    QLabel *lab1 = new QLabel("输入密码：", frame);
    QLabel *lab2 = new QLabel("二次输入密码：", frame);
    QLabel *lab3 = new QLabel("输入秘钥存储服务器地址：", frame);
    QLabel *lab4 = new QLabel("选择秘钥导出位置：", frame);

    passwd1 = new DPasswordEdit(frame);
    passwd2 = new DPasswordEdit(frame);
    serverAddr = new DLineEdit(frame);
    exportPath = new DFileChooserEdit(frame);

    lay->addWidget(lab1);
    lay->addWidget(passwd1);
    lay->addWidget(lab2);
    lay->addWidget(passwd2);
    lay->addWidget(lab4);
    lay->addWidget(exportPath);
    lay->addWidget(lab3);
    lay->addWidget(serverAddr);

    addButtons({ "取消", "确认" });
    setTitle("加密磁盘：" + device);
    exportPath->setFileMode(QFileDialog::Directory);
}

void EncryptParamsInputDialog::initConn()
{
    connect(this, &EncryptParamsInputDialog::buttonClicked, this, &EncryptParamsInputDialog::onButtonClicked);
}

void EncryptParamsInputDialog::onButtonClicked(int idx)
{
    if (idx == 0) {
        reject();
        return;
    }

    QString p1 = passwd1->text();
    QString p2 = passwd2->text();
    QString savePath = exportPath->text();

    if (p1.isEmpty()) {
        QToolTip::showText(passwd1->mapToGlobal(passwd1->pos()), "密码不能为空！");
        return;
    }
    if (p2.isEmpty()) {
        QToolTip::showText(passwd1->mapToGlobal(passwd2->pos()), "密码不能为空！");
        return;
    }

    if (p1 != p2) {
        QToolTip::showText(passwd1->mapToGlobal(passwd1->pos()), "两次密码输入必须一致！");
        return;
    }

    if (savePath.isEmpty()) {
        QToolTip::showText(passwd1->mapToGlobal(exportPath->pos()), "秘钥导出路径不能为空！");
        return;
    }

    accept();
}
