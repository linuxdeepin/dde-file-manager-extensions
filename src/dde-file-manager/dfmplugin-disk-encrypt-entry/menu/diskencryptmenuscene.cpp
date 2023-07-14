// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "diskencryptmenuscene.h"
#include "gui/encryptparamsinputdialog.h"
#include "gui/encryptprocessdialog.h"

#include <dfm-base/dfm_menu_defines.h>
#include <dfm-base/base/schemefactory.h>
#include <dfm-base/interfaces/fileinfo.h>

#include <QDebug>
#include <QMenu>
#include <QProcess>
#include <QFile>
#include <QStringList>

DFMBASE_USE_NAMESPACE
using namespace dfmplugin_diskenc;

int showUploadErrorDialog()
{
    DDialog dlg;
    dlg.setTitle("错误");
    dlg.setMessage("上传秘钥文件失败，重新传输？");
    dlg.addButton("取消");
    dlg.addButton("重新传输", true, DDialog::ButtonRecommend);
    return dlg.exec();
}

void showUploadFinishedDialog()
{
    DDialog dlg;
    dlg.setTitle("磁盘加密预设完成");
    dlg.setMessage("秘钥上传成功，请重启以完成磁盘加密。");
    dlg.addButton("确认");
    dlg.exec();
}

void showEncryptErrorDialog()
{
    DDialog dlg;
    dlg.setTitle("错误");
    dlg.setMessage("加密磁盘失败，请查看日志以获取详细信息。");
    dlg.addButton("确认");
    dlg.exec();
}

void doUploadKeyFile(const QString &filePath, const QString &server)
{
    QStringList params;
    params << filePath
           << server;

    qInfo() << "#######  uploading... key_upload.sh" << params;

    QString *errMsg = new QString;
    QProcess *p = new QProcess;
    QObject::connect(p, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
                     qApp, [=](int /*code*/) {
                         p->deleteLater();

                         *errMsg += QString(p->readAll());
                         *errMsg += QString(p->readAllStandardError());
                         *errMsg += QString(p->readAllStandardOutput());
                         qInfo() << "#######  upload info: " << *errMsg;

                         QString msg = *errMsg;
                         delete errMsg;

                         if (msg.contains("200")) {
                             qInfo() << "#######  upload finished";
                             showUploadFinishedDialog();
                         } else {
                             bool reUpload = (showUploadErrorDialog() == QDialog::Accepted);
                             if (reUpload) {
                                 qInfo() << "#######  upload failed, reupload.";
                                 doUploadKeyFile(filePath, server);
                             }
                         }
                     });
    QObject::connect(p, &QProcess::readyReadStandardError, qApp, [=]() {
        *errMsg += QString(p->readAllStandardError());
        qInfo() << "#######  upload new error: " << *errMsg;
    });
    QObject::connect(p, &QProcess::readyReadStandardOutput, qApp, [=]() {
        *errMsg += QString(p->readAllStandardOutput());
        qInfo() << "#######  upload new info: " << *errMsg;
    });

    p->start("key_upload.sh", params);
}

void doEncryptDisk(ParamsInputs inputs)
{
    //    QStringList params;
    //    params << inputs.devDesc << inputs.passwd << inputs.exportPath;

    //    //    EncryptProcessDialog *processDlg = new EncryptProcessDialog(inputs.devDesc);
    //    QProcess *p = new QProcess;
    //    QObject::connect(p, static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
    //                     qApp, [=](int /*code*/) {
    //                         p->deleteLater();
    //                         //                         processDlg->encryptDone();
    //                         //                         processDlg->deleteLater();

    //                         if (QFile(inputs.exportPath).exists())
    //                             doUploadKeyFile(inputs.exportPath, inputs.serverAddr);
    //                         else
    //                             showEncryptErrorDialog();
    //                     });
    //    QObject::connect(p, &QProcess::readyReadStandardError, qApp, [=]() {
    //        qInfo() << "#######  new error: " << p->readAllStandardError();
    //    });
    //    QObject::connect(p, &QProcess::readyReadStandardOutput, qApp, [=]() {
    //        qInfo() << "#######  new info: " << p->readAllStandardOutput();
    //    });
    //    params.prepend("blockcrypt.sh");
    //    p->start("pkexec", params);
    //    qInfo() << "#######  executing... blockcrypt" << params;
    //    //    processDlg->startEncrypt();
    //    //    processDlg->show();
}

DiskEncryptMenuScene::DiskEncryptMenuScene(QObject *parent)
    : AbstractMenuScene(parent)
{
}

dfmbase::AbstractMenuScene *DiskEncryptMenuCreator::create()
{
    return new DiskEncryptMenuScene();
}

QString DiskEncryptMenuScene::name() const
{
    return DiskEncryptMenuCreator::name();
}

bool DiskEncryptMenuScene::initialize(const QVariantHash &params)
{
    QList<QUrl> selectedItems = params.value(MenuParamKey::kSelectFiles).value<QList<QUrl>>();
    if (selectedItems.isEmpty())
        return false;

    selectedItem = selectedItems.first();
    if (!selectedItem.path().endsWith("blockdev"))
        return false;

    QSharedPointer<FileInfo> info = InfoFactory::create<FileInfo>(selectedItem);
    if (!info)
        return false;

    QVariantHash extProps = info->extraProperties();
    devDesc = extProps.value("Device", "").toString();
    if (devDesc.isEmpty())
        return false;
    return true;
}

bool DiskEncryptMenuScene::create(QMenu *parent)
{
    Q_ASSERT(parent);
    actEncrypt = parent->addAction("加密磁盘");
    return true;
}

bool DiskEncryptMenuScene::triggered(QAction *action)
{
    if (action == actEncrypt) {
        EncryptParamsInputDialog *dlg = new EncryptParamsInputDialog(devDesc);
        connect(dlg, &EncryptParamsInputDialog::finished, qApp, [=](int result) {
            if (result == QDialog::Accepted)
                doEncryptDisk(dlg->getInputs());
            dlg->deleteLater();
        });
        dlg->show();
        return true;
    }
    return false;
}

void DiskEncryptMenuScene::updateState(QMenu *parent)
{
    Q_ASSERT(parent);
    QList<QAction *> acts = parent->actions();
    for (auto act : acts) {
        if (act == actEncrypt) {
            actEncrypt->setVisible(true);
            break;
        }
    }
}
