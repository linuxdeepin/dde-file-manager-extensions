// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dfmplugin_disk_encrypt_global.h"
#include "diskencryptmenuscene.h"
#include "gui/encryptparamsinputdialog.h"
#include "gui/decryptparamsinputdialog.h"
#include "gui/chgpassphrasedialog.h"
#include "utils/encryptutils.h"

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
#include <dconfig.h>

#include <fstab.h>

DFMBASE_USE_NAMESPACE
using namespace dfmplugin_diskenc;

static constexpr char kActIDEncrypt[] { "de_0_encrypt" };
static constexpr char kActIDDecrypt[] { "de_1_decrypt" };
static constexpr char kActIDChangePwd[] { "de_2_changePwd" };

inline constexpr char kKeyDevice[] { "device" };
inline constexpr char kKeyUUID[] { "uuid" };
inline constexpr char kKeyEncMode[] { "mode" };
inline constexpr char kKeyPassphrase[] { "passphrase" };
inline constexpr char kKeyOldPassphrase[] { "oldPassphrase" };
inline constexpr char kKeyCipher[] { "cipher" };
inline constexpr char kKeyRecoveryExportPath[] { "exportRecKeyTo" };
inline constexpr char kKeyInitParamsOnly[] { "initParamsOnly" };

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
    info->refresh();

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

    QString devMpt = extProps.value("MountPoint", "").toString();
    operatingFstabDevice = fstab_utils::isFstabItem(devMpt);
    uuid = extProps.value("IdUUID", "").toString();
    return true;
}

bool DiskEncryptMenuScene::create(QMenu *)
{
    if (itemEncrypted) {
        QAction *act = new QAction(tr("Deencrypt"));
        act->setProperty(ActionPropertyKey::kActionID, kActIDDecrypt);
        actions.insert(kActIDDecrypt, act);

        act = new QAction(tr("Change passphrase"));
        act->setProperty(ActionPropertyKey::kActionID, kActIDChangePwd);
        actions.insert(kActIDChangePwd, act);
    } else {
        QAction *act = new QAction(tr("Encrypt"));
        act->setProperty(ActionPropertyKey::kActionID, kActIDEncrypt);
        actions.insert(kActIDEncrypt, act);
    }

    return true;
}

bool DiskEncryptMenuScene::triggered(QAction *action)
{
    QString actID = action->property(ActionPropertyKey::kActionID).toString();

    if (actID == kActIDEncrypt)
        operatingFstabDevice ? encryptDevice(devDesc, uuid, true) : unmountBefore(encryptDevice);
    else if (actID == kActIDDecrypt)
        operatingFstabDevice ? deencryptDevice(devDesc, uuid, true) : unmountBefore(deencryptDevice);
    else if (actID == kActIDChangePwd)
        changePassphrase(devDesc, uuid, true);
    else
        return false;
    return true;
}

void DiskEncryptMenuScene::updateState(QMenu *parent)
{
    Q_ASSERT(parent);
    QList<QAction *> acts = parent->actions();
    QAction *before { nullptr };
    for (int i = 0; i < acts.count(); ++i) {
        auto act = acts.at(i);
        QString actID = act->property(ActionPropertyKey::kActionID).toString();
        if (actID == "computer-rename"   // the encrypt actions should be under computer-rename
            && (i + 1) < acts.count()) {
            before = acts.at(i + 1);
            break;
        }
    }

    if (!before)
        before = acts.last();

    std::for_each(actions.begin(), actions.end(), [=](QAction *val) {
        parent->insertAction(before, val);
        val->setParent(parent);
    });
}

void DiskEncryptMenuScene::encryptDevice(const QString &dev, const QString &uuid, bool paramsOnly)
{
    EncryptParamsInputDialog *dlg = new EncryptParamsInputDialog(dev);
    connect(dlg, &EncryptParamsInputDialog::finished, qApp, [=](int result) {
        dlg->deleteLater();
        if (result == QDialog::Accepted) {
            auto params = dlg->getInputs();
            params.initOnly = paramsOnly;
            params.uuid = uuid;
            doEncryptDevice(params);
        }
    });
    dlg->show();
}

void DiskEncryptMenuScene::deencryptDevice(const QString &dev, const QString & /*uuid*/, bool paramsOnly)
{
    DecryptParamsInputDialog *dlg = new DecryptParamsInputDialog(dev);
    connect(dlg, &DecryptParamsInputDialog::finished, qApp, [=](int result) {
        dlg->deleteLater();
        if (result == 0) {
            auto inputs = dlg->getInputs();
            doDecryptDevice(inputs.first, inputs.second, paramsOnly);
        }
    });
    dlg->show();
}

void DiskEncryptMenuScene::changePassphrase(const QString &dev, const QString & /*uuid*/, bool paramsOnly)
{
    ChgPassphraseDialog *dlg = new ChgPassphraseDialog(dev);
    connect(dlg, &ChgPassphraseDialog::finished, qApp, [=](int result) {
        dlg->deleteLater();
        if (result == 1) {
            auto inputs = dlg->getPassphrase();
            doChangePassphrase(dev, inputs.second, inputs.first);
        }
    });
    dlg->show();
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
            { kKeyDevice, inputs.devDesc },
            { kKeyUUID, inputs.uuid },
            { kKeyCipher, config_utils::cipherType() },
            { kKeyPassphrase, inputs.key },
            { kKeyInitParamsOnly, inputs.initOnly },
            { kKeyRecoveryExportPath, inputs.exportPath },
            { kKeyEncMode, inputs.type },
        };
        QDBusReply<QString> reply = iface.call("PrepareEncryptDisk", params);
        qDebug() << "preencrypt device jobid:" << reply.value();
        QApplication::setOverrideCursor(Qt::WaitCursor);
    }
}

void DiskEncryptMenuScene::doDecryptDevice(const QString &dev, const QString &passphrase, bool paramsOnly)
{
    // if tpm selected, use tpm to generate the key
    QDBusInterface iface(kDaemonBusName,
                         kDaemonBusPath,
                         kDaemonBusIface,
                         QDBusConnection::systemBus());
    if (iface.isValid()) {
        QVariantMap params {
            { kKeyDevice, dev },
            { kKeyPassphrase, passphrase },
            { kKeyInitParamsOnly, paramsOnly }
        };
        QDBusReply<QString> reply = iface.call("DecryptDisk", params);
        qDebug() << "preencrypt device jobid:" << reply.value();
    }
}

void DiskEncryptMenuScene::doChangePassphrase(const QString &dev, const QString oldPass, const QString &newPass)
{
    QDBusInterface iface(kDaemonBusName,
                         kDaemonBusPath,
                         kDaemonBusIface,
                         QDBusConnection::systemBus());
    if (iface.isValid()) {
        QVariantMap params {
            { kKeyDevice, dev },
            { kKeyPassphrase, newPass },
            { kKeyOldPassphrase, oldPass }
        };
        QDBusReply<QString> reply = iface.call("ChangeEncryptPassphress", params);
        qDebug() << "modify device passphrase jobid:" << reply.value();
        QApplication::setOverrideCursor(Qt::WaitCursor);
    }
}

void DiskEncryptMenuScene::unmountBefore(const std::function<void(const QString &, const QString &, bool)> &after)
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
    QString devUUID(uuid);
    bool writeParamsOnly = operatingFstabDevice;
    if (blk->isEncrypted()) {
        const QString &clearPath = blk->getProperty(Property::kEncryptedCleartextDevice).toString();
        if (clearPath.length() > 1) {
            auto lock = [=] {
                blk->lockAsync({}, [=](bool ok, OperationErrorInfo err) {
                    if (ok)
                        after(device, devUUID, writeParamsOnly);
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
            after(device, devUUID, writeParamsOnly);
        }
    } else {
        blk->unmountAsync({}, [=](bool ok, OperationErrorInfo err) {
            if (ok)
                after(device, devUUID, writeParamsOnly);
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
