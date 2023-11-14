// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "eventshandler.h"
#include "dfmplugin_disk_encrypt_global.h"
#include "gui/encryptparamsinputdialog.h"
#include "gui/encryptprocessdialog.h"
#include "gui/unlockpartitiondialog.h"
#include "utils/encryptutils.h"

#include <dfm-framework/dpf.h>

#include <QApplication>
#include <QSettings>
#include <QDBusConnection>

#include <DDialog>

Q_DECLARE_METATYPE(QString *)
Q_DECLARE_METATYPE(bool *)

using namespace dfmplugin_diskenc;
DWIDGET_USE_NAMESPACE;

EventsHandler *EventsHandler::instance()
{
    static EventsHandler ins;
    return &ins;
}

void EventsHandler::bindDaemonSignals()
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

void EventsHandler::hookEvents()
{
    dpfHookSequence->follow("dfmplugin_computer", "hook_Device_AcquireDevPwd",
                            this, &EventsHandler::onAcquireDevicePwd);
}

void EventsHandler::onPreencryptResult(const QString &dev, const QString &, int code)
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

    DDialog dlg;
    dlg.setTitle(title);
    dlg.setMessage(msg);
    dlg.addButton(tr("Confirm"));
    dlg.exec();
}

void EventsHandler::onEncryptResult(const QString &dev, int code)
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

    DDialog dlg;
    dlg.setTitle(title);
    dlg.setMessage(msg);
    dlg.addButton(tr("Confirm"));
    dlg.exec();
}

void EventsHandler::onDecryptResult(const QString &dev, const QString &job, int code)
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

    DDialog dlg;
    dlg.setTitle(title);
    dlg.setMessage(msg);
    dlg.addButton(tr("Confirm"));
    dlg.exec();
}

void EventsHandler::onChgPassphraseResult(const QString &dev, const QString &, int code)
{
    QApplication::restoreOverrideCursor();

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

    DDialog dlg;
    dlg.setTitle(title);
    dlg.setMessage(msg);
    dlg.addButton(tr("Confirm"));
    dlg.exec();
}

void EventsHandler::onEncryptProgress(const QString &dev, double progress)
{
    if (!encryptDialogs.contains(dev))
        encryptDialogs.insert(dev, new EncryptProcessDialog(tr("Encrypting...%1").arg(dev)));
    auto dlg = encryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();
}

void EventsHandler::onDecryptProgress(const QString &dev, double progress)
{
    if (!decryptDialogs.contains(dev))
        decryptDialogs.insert(dev, new EncryptProcessDialog(tr("Decrypting...%1").arg(dev)));
    auto dlg = decryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();
}

bool EventsHandler::onAcquireDevicePwd(const QString &dev, QString *pwd, bool *cancelled)
{
    if (!pwd || !cancelled)
        return false;

    int type = device_utils::encKeyType(dev);
    switch (type) {
    case SecKeyType::kTPMAndPIN:
        *pwd = acquirePassphraseByPIN(dev, *cancelled);
        break;
    case SecKeyType::kTPMOnly:
        *pwd = acquirePassphraseByTPM(dev, *cancelled);
        break;
    case SecKeyType::kPasswordOnly:
        *pwd = acquirePassphrase(dev, *cancelled);
        break;
    default:
        break;
    }

    if (pwd->isEmpty() && !*cancelled) {
        QString title;
        if (type == kTPMAndPIN)
            title = tr("Wrong PIN");
        else if (type == kPasswordOnly)
            title = tr("Wrong passphrase");
        else
            title = tr("TPM error");

        DDialog dlg;
        dlg.setTitle(title);
        dlg.setMessage(tr("Please use recovery key to unlock device."));
        dlg.addButton(tr("Confirm"));
        dlg.exec();

        *cancelled = true;
    }

    return true;
}

QString EventsHandler::acquirePassphrase(const QString &dev, bool &cancelled)
{
    UnlockPartitionDialog dlg(UnlockPartitionDialog::kPwd);
    int ret = dlg.exec();
    if (ret != 1) {
        cancelled = true;
        return "";
    }
    return dlg.getUnlockKey().second;
}

QString EventsHandler::acquirePassphraseByPIN(const QString &dev, bool &cancelled)
{
    UnlockPartitionDialog dlg(UnlockPartitionDialog::kPin);
    int ret = dlg.exec();
    if (ret != 1) {
        cancelled = true;
        return "";
    }
    auto keys = dlg.getUnlockKey();
    if (keys.first == UnlockPartitionDialog::kPin)
        return tpm_passphrase_utils::getPassphraseFromTPM(dev, keys.second);
    else
        return keys.second;
}

QString EventsHandler::acquirePassphraseByTPM(const QString &dev, bool &)
{
    return tpm_passphrase_utils::getPassphraseFromTPM(dev, "");
}

EventsHandler::EventsHandler(QObject *parent)
    : QObject { parent }
{
}
