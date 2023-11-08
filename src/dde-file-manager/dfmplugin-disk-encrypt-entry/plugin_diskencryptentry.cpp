// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "plugin_diskencryptentry.h"
#include "menu/diskencryptmenuscene.h"
#include "gui/encryptprocessdialog.h"
#include "gui/acquirepindialog.h"
#include "utils/encryptutils.h"

#include <QApplication>
#include <QDebug>
#include <QDBusConnection>
#include <QTranslator>
#include <QSettings>

#include <ddialog.h>

static constexpr char kMenuPluginName[] { "dfmplugin_menu" };
static constexpr char kComputerMenuSceneName[] { "ComputerMenu" };

Q_DECLARE_METATYPE(QString *)
using namespace dfmplugin_diskenc;

bool hasComputerMenuRegisted()
{
    return dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_Contains", QString(kComputerMenuSceneName)).toBool();
}

void DiskEncryptEntry::initialize()
{
    auto i18n = new QTranslator(this);
    i18n->load(QLocale(), "disk-encrypt", "_", "/usr/share/dde-file-manager/translations");
    QCoreApplication::installTranslator(i18n);
}

bool DiskEncryptEntry::start()
{
    dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_RegisterScene",
                         DiskEncryptMenuCreator::name(), new DiskEncryptMenuCreator);

    if (hasComputerMenuRegisted()) {
        dpfSlotChannel->push("dfmplugin_menu", "slot_MenuScene_Bind",
                             DiskEncryptMenuCreator::name(), QString(kComputerMenuSceneName));
    } else {
        dpfSignalDispatcher->subscribe(kMenuPluginName, "signal_MenuScene_SceneAdded",
                                       this, &DiskEncryptEntry::onComputerMenuSceneAdded);
    }

    connectDaemonSignals();

    dpfHookSequence->follow("dfmplugin_computer", "hook_Device_AcquireDevPwd",
                            this, &DiskEncryptEntry::onAcquireDevicePwd);

    return true;
}

void DiskEncryptEntry::connectDaemonSignals()
{
    auto conn = [this](const char *sig, const char *slot) {
        QDBusConnection::systemBus().connect(kDaemonBusName,
                                             kDaemonBusPath,
                                             kDaemonBusIface,
                                             sig,
                                             this,
                                             slot);
    };
    conn("PrepareEncryptDiskResult", SLOT(onPreencryptResult(const QString &, const QString &, int)));
    conn("EncryptDiskResult", SLOT(onEncryptResult(const QString &, int)));
    conn("EncryptProgress", SLOT(onEncryptProgress(const QString &, double)));
    conn("DecryptDiskResult", SLOT(onDecryptResult(const QString &, const QString &, int)));
    conn("DecryptProgress", SLOT(onDecryptProgress(const QString &, double)));
    conn("ChangePassphressResult", SLOT(onChgPassphraseResult(const QString &, const QString &, int)));
}

void DiskEncryptEntry::onPreencryptResult(const QString &dev, const QString &, int code)
{
    QApplication::restoreOverrideCursor();

    QString title;
    QString msg;
    switch (code) {
    case (EncryptJobError::kNoError):
        title = tr("Preencrypt done");
        msg = tr("Device %1 has been preencrypt, please reboot to finish encryption.")
                      .arg(dev);
        break;
    case EncryptJobError::kUserCancelled:
        title = tr("Encrypt disk");
        msg = tr("User cancelled operation");
        break;
    default:
        title = tr("Preencrypt failed");
        msg = tr("Device %1 preencrypt failed, please see log for more information.(%2)")
                      .arg(dev)
                      .arg(code);
        break;
    }

    DDialog *dlg = new DDialog;
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setTitle(title);
    dlg->setMessage(msg);
    dlg->addButton(tr("Confirm"));
    dlg->show();
}

void DiskEncryptEntry::onEncryptResult(const QString &dev, int code)
{
    if (encryptDialogs.contains(dev)) {
        delete encryptDialogs.value(dev);
        encryptDialogs.remove(dev);
    }

    QString title = tr("Encrypt done");
    QString msg = tr("Device %1 has been encrypted").arg(dev);
    if (code != 0) {
        title = tr("Encrypt failed");
        msg = tr("Device %1 encrypt failed, please see log for more information.(%2)")
                      .arg(dev)
                      .arg(code);
    }

    DDialog *dlg = new DDialog;
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setTitle(title);
    dlg->setMessage(msg);
    dlg->addButton(tr("Confirm"));
    dlg->show();
}

void DiskEncryptEntry::onEncryptProgress(const QString &dev, double progress)
{
    if (!encryptDialogs.contains(dev))
        encryptDialogs.insert(dev, new EncryptProcessDialog(tr("Encrypting...%1").arg(dev)));
    auto dlg = encryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();
}

void DiskEncryptEntry::onDecryptResult(const QString &dev, const QString &job, int code)
{
    if (decryptDialogs.contains(dev)) {
        decryptDialogs.value(dev)->deleteLater();
        decryptDialogs.remove(dev);
    }

    QString title;
    QString msg;
    switch (code) {
    case (EncryptJobError::kNoError):
        title = tr("Decrypt done");
        msg = tr("Device %1 has been decrypted").arg(dev);
        break;
    case EncryptJobError::kUserCancelled:
        title = tr("Decrypt disk");
        msg = tr("User cancelled operation");
        break;
    default:
        title = tr("Decrypt failed");
        msg = tr("Device %1 Decrypt failed, please see log for more information.(%2)")
                      .arg(dev)
                      .arg(code);
        break;
    }

    DDialog *dlg = new DDialog;
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setTitle(title);
    dlg->setMessage(msg);
    dlg->addButton(tr("Confirm"));
    dlg->show();
}

void DiskEncryptEntry::onDecryptProgress(const QString &dev, double progress)
{
    if (!decryptDialogs.contains(dev))
        decryptDialogs.insert(dev, new EncryptProcessDialog(tr("Decrypting...%1").arg(dev)));
    auto dlg = decryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();
}

void DiskEncryptEntry::onChgPassphraseResult(const QString &dev, const QString &, int code)
{
    QString title;
    QString msg;
    switch (code) {
    case (EncryptJobError::kNoError):
        title = tr("Change passphrase done");
        msg = tr("%1's passphrase has been changed").arg(dev);
        break;
    case EncryptJobError::kUserCancelled:
        title = tr("Change passphrase");
        msg = tr("User cancelled operation");
        break;
    default:
        title = tr("Change passphrase failed");
        msg = tr("Device %1 change passphrase failed, please see log for more information.(%2)")
                      .arg(dev)
                      .arg(code);
        break;
    }

    DDialog *dlg = new DDialog;
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setTitle(title);
    dlg->setMessage(msg);
    dlg->addButton(tr("Confirm"));
    dlg->show();
}

bool DiskEncryptEntry::onAcquireDevicePwd(const QString &dev, QString *pwd)
{
    if (!pwd)
        return false;

    auto showTPMError = [] {
        DDialog dlg;
        dlg.setTitle(tr("TPM Error"));
        dlg.setMessage(tr("Cannot acquire key from TPM, please use recovery key to unlock device."));
        dlg.addButton(tr("Confirm"));
        dlg.exec();
    };

    QSettings sets(DEV_ENCTYPE_CFG, QSettings::IniFormat);
    int type = sets.value(DEV_KEY.arg(dev.mid(5)), -1).toInt();
    switch (type) {
    case SecKeyType::kTPMAndPIN: {
        AcquirePinDialog dlg(tr("Please input PIN to unlock device %1").arg(dev));
        int ret = dlg.exec();
        QString pin = dlg.getUerInputedPassword();
        bool ok = tpm_utils::decryptByTPM(pin, kTPMKeyPath + dev, pwd);
        if (!ok && ret == 1)
            showTPMError();

        qInfo() << "DEBUG INFORMATION>>>>>>>>>>>>>>>   TPM pwd for device:"
                << dev
                << *pwd;
        return ok;
    }
    case SecKeyType::kTPMOnly: {
        bool ok = tpm_utils::decryptByTPM("", kTPMKeyPath + dev, pwd);
        if (!ok)
            showTPMError();
        qInfo() << "DEBUG INFORMATION>>>>>>>>>>>>>>>   TPM pwd for device:"
                << dev
                << *pwd;
        return ok;
    }
    default:
        return false;
    }

    return true;
}

void DiskEncryptEntry::onComputerMenuSceneAdded(const QString &scene)
{
    if (scene == "ComputerMenu") {
        dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_Bind", DiskEncryptMenuCreator::name(), kComputerMenuSceneName);
        dpfSignalDispatcher->unsubscribe("dfmplugin_menu", "signal_MenuScene_SceneAdded", this, &DiskEncryptEntry::onComputerMenuSceneAdded);
    }
}
