// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dfmplugin_disk_encrypt_global.h"
#include "diskencryptmenuscene.h"
#include "gui/encryptparamsinputdialog.h"
#include "gui/decryptparamsinputdialog.h"

#include <dfm-base/dfm_menu_defines.h>
#include <dfm-base/base/schemefactory.h>
#include <dfm-base/interfaces/fileinfo.h>

#include <QDebug>
#include <QMenu>
#include <QProcess>
#include <QFile>
#include <QStringList>
#include <QDBusInterface>
#include <QDBusReply>
#include <QApplication>

#include <ddialog.h>

DFMBASE_USE_NAMESPACE
using namespace dfmplugin_diskenc;

static constexpr char kActIDEncrypt[] { "de_encrypt" };
static constexpr char kActIDDecrypt[] { "de_decrypt" };
static constexpr char kActIDChangePwd[] { "de_changePwd" };

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

    const QString &idType = extProps.value("IdType").toString();
    const QString &idVersion = extProps.value("IdVersion").toString();
    const QStringList &supportedFS { "ext4", "ext3", "ext2" };
    if (idType == "crypto_LUKS") {
        if (idVersion == "1")
            return false;
        itemEncrypted = true;
    } else if (!supportedFS.contains(idType)) {
        return false;
    }

    //    const QString &config = extProps.value("Configuration").toString();
    //    qDebug() << "<<<<<<<<<<<<<<<   " << config;
    //    if (config.contains("fstab"))
    //        return false;

    return true;
}

bool DiskEncryptMenuScene::create(QMenu *parent)
{
    Q_ASSERT(parent);

    if (itemEncrypted) {
        QAction *act = parent->addAction(tr("Deencrypt"));
        act->setProperty(ActionPropertyKey::kActionID, kActIDDecrypt);

        act = parent->addAction(tr("Change passphrase"));
        act->setProperty(ActionPropertyKey::kActionID, kActIDChangePwd);
    } else {
        QAction *act = parent->addAction(tr("Encrypt"));
        act->setProperty(ActionPropertyKey::kActionID, kActIDEncrypt);
    }

    return true;
}

bool DiskEncryptMenuScene::triggered(QAction *action)
{
    QString actID = action->property(ActionPropertyKey::kActionID).toString();
    if (actID == kActIDEncrypt)
        unmountBefore(encryptDevice);
    else if (actID == kActIDDecrypt)
        unmountBefore(deencryptDevice);
    else if (actID == kActIDChangePwd)
        unmountBefore(changePassphrase);
    else
        return false;
    return true;
}

void DiskEncryptMenuScene::updateState(QMenu *parent)
{
    Q_ASSERT(parent);
    QList<QAction *> acts = parent->actions();
    for (auto act : acts) {
        QString actID = act->property(ActionPropertyKey::kActionID).toString();
        if (actID == kActIDEncrypt
            || actID == kActIDDecrypt
            || actID == kActIDChangePwd)
            act->setVisible(true);
    }
}

void DiskEncryptMenuScene::encryptDevice(const QString &dev)
{
    EncryptParamsInputDialog *dlg = new EncryptParamsInputDialog(dev);
    connect(dlg, &EncryptParamsInputDialog::finished, qApp, [=](int result) {
        dlg->deleteLater();
        if (result == QDialog::Accepted)
            doEncryptDevice(dlg->getInputs());
    });
    dlg->show();
}

void DiskEncryptMenuScene::deencryptDevice(const QString &dev)
{
    DecryptParamsInputDialog *dlg = new DecryptParamsInputDialog(dev);
    connect(dlg, &DecryptParamsInputDialog::finished, qApp, [=](int result) {
        dlg->deleteLater();
        qDebug() << "#########  " << result;
        if (result == 0) {
            auto inputs = dlg->getInputs();
            doDecryptDevice(inputs.first, inputs.second);
        }
    });
    dlg->show();
}

void DiskEncryptMenuScene::changePassphrase(const QString &dev)
{
}

void DiskEncryptMenuScene::doEncryptDevice(const ParamsInputs &inputs)
{
    // if tpm selected, use tpm to generate the key
    QDBusInterface iface(kDaemonBusName,
                         kDaemonBusPath,
                         kDaemonBusIface,
                         QDBusConnection::systemBus());
    if (iface.isValid()) {
        QVariantMap params {
            { "device", inputs.devDesc },
            { "cipher", QString("sm4") },
            { "passphrase", inputs.key }
        };
        QDBusReply<QString> reply = iface.call("PrepareEncryptDisk", params);
        qDebug() << "preencrypt device jobid:" << reply.value();
        QApplication::setOverrideCursor(Qt::WaitCursor);
    }
}

void DiskEncryptMenuScene::doDecryptDevice(const QString &dev, const QString &passphrase)
{
    // if tpm selected, use tpm to generate the key
    QDBusInterface iface(kDaemonBusName,
                         kDaemonBusPath,
                         kDaemonBusIface,
                         QDBusConnection::systemBus());
    if (iface.isValid()) {
        QVariantMap params {
            { "device", dev },
            { "passphrase", passphrase }
        };
        QDBusReply<QString> reply = iface.call("DecryptDisk", params);
        qDebug() << "preencrypt device jobid:" << reply.value();
    }
}

void DiskEncryptMenuScene::unmountBefore(const std::function<void(const QString &)> &after)
{
    using namespace dfmmount;
    auto mng = DDeviceManager::instance()
                       ->getRegisteredMonitor(DeviceType::kBlockDevice)
                       .objectCast<DBlockMonitor>();
    Q_ASSERT(mng);

    QStringList objPaths = mng->resolveDeviceNode(devDesc, {});
    if (objPaths.isEmpty()) {
        qWarning() << "cannot resolve objpath of" << devDesc;
        return;
    }
    auto blk = mng->createDeviceById(objPaths.constFirst())
                       .objectCast<DBlockDevice>();
    if (!blk)
        return;

    QString device(devDesc);
    if (blk->isEncrypted()) {
        const QString &clearPath = blk->getProperty(Property::kEncryptedCleartextDevice).toString();
        if (clearPath.length() > 1) {
            auto lock = [=] {
                blk->lockAsync({}, [=](bool ok, OperationErrorInfo err) {
                    if (ok)
                        after(device);
                    else
                        onUnmountError(kLock, device, err);
                });
            };
            auto onUnmounted = [=](bool ok, const OperationErrorInfo &err) {
                if (ok)
                    lock();
                else
                    onUnmountError(kUnmount, device, err);
            };

            // do unmount cleardev
            auto clearDev = mng->createDeviceById(clearPath);
            clearDev->unmountAsync({}, onUnmounted);
        } else {
            after(device);
        }
    } else {
        blk->unmountAsync({}, [=](bool ok, OperationErrorInfo err) {
            if (ok)
                after(device);
            else
                onUnmountError(kUnmount, device, err);
        });
    }
}

void DiskEncryptMenuScene::onUnmountError(OpType t, const QString &dev, const dfmmount::OperationErrorInfo &err)
{
    qDebug() << "unmount device failed:"
             << dev
             << err.message;
    QString operation = (t == kUnmount) ? tr("unmount") : tr("lock");
    Dtk::Widget::DDialog d;
    d.setTitle(tr("Encrypt failed"));
    d.setMessage(tr("Cannot %1 device %2").arg(operation, dev));
    d.addButton(tr("Close"));
    d.exec();
}
