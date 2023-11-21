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
#include <QDBusInterface>
#include <QDBusPendingCall>

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

bool EventsHandler::hasEnDecryptJob()
{
    return !(encryptDialogs.isEmpty() && decryptDialogs.isEmpty());
}

void EventsHandler::onPreencryptResult(const QString &dev, const QString &, int code)
{
    QApplication::restoreOverrideCursor();

    if (code != EncryptJobError::kNoError) {
        showPreEncryptError(dev, code);
        return;
    }
    showReboot(dev);
}

void EventsHandler::onEncryptResult(const QString &dev, int code)
{
    QApplication::restoreOverrideCursor();
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

    dialog_utils::showDialog(title, msg, code != 0 ? dialog_utils::kError : dialog_utils::kInfo);
}

void EventsHandler::onDecryptResult(const QString &dev, const QString &, int code)
{
    QApplication::restoreOverrideCursor();
    if (decryptDialogs.contains(dev)) {
        decryptDialogs.value(dev)->deleteLater();
        decryptDialogs.remove(dev);
    }

    showDecryptError(dev, code);
}

void EventsHandler::onChgPassphraseResult(const QString &dev, const QString &, int code)
{
    QApplication::restoreOverrideCursor();
    showChgPwdError(dev, code);
}

void EventsHandler::onEncryptProgress(const QString &dev, double progress)
{
    if (!encryptDialogs.contains(dev)) {
        QApplication::restoreOverrideCursor();
        auto dlg = new EncryptProcessDialog(tr("Encrypting...%1").arg(dev));
        connect(dlg, &EncryptProcessDialog::destroyed,
                this, [this, dev] { encryptDialogs.remove(dev); });
        encryptDialogs.insert(dev, dlg);
    }
    auto dlg = encryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();
}

void EventsHandler::onDecryptProgress(const QString &dev, double progress)
{
    if (!decryptDialogs.contains(dev)) {
        QApplication::restoreOverrideCursor();
        decryptDialogs.insert(dev, new EncryptProcessDialog(tr("Decrypting...%1").arg(dev)));
    }

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
        return false;
    }

    if (pwd->isEmpty() && !*cancelled) {
        QString title;
        if (type == kTPMAndPIN)
            title = tr("Wrong PIN");
        else if (type == kPasswordOnly)
            title = tr("Wrong passphrase");
        else
            title = tr("TPM error");

        dialog_utils::showDialog(title, tr("Please use recovery key to unlock device."),
                                 dialog_utils::kInfo);
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

void EventsHandler::showPreEncryptError(const QString &dev, int code)
{
    QString title;
    QString msg;
    bool showError = false;
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
        showError = true;
        break;
    }

    dialog_utils::showDialog(title, msg,
                             showError ? dialog_utils::kError : dialog_utils::kInfo);
}

void EventsHandler::showDecryptError(const QString &dev, int code)
{
    QString title;
    QString msg;
    bool showFailed = false;
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
        showFailed = true;
        break;
    }

    dialog_utils::showDialog(title, msg,
                             showFailed ? dialog_utils::kError : dialog_utils::kInfo);
}

void EventsHandler::showChgPwdError(const QString &dev, int code)
{

    QString title;
    QString msg;
    bool showError = false;
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
        showError = true;
        break;
    }

    dialog_utils::showDialog(title, msg,
                             showError ? dialog_utils::kError : dialog_utils::kInfo);
}

void EventsHandler::showReboot(const QString &device)
{
    DDialog dlg;
    dlg.setIcon(QIcon::fromTheme("dialog-info"));
    dlg.setTitle(tr("Preencrypt done"));
    dlg.setMessage(tr("Device %1 has been preencrypt, please reboot to finish encryption.")
                           .arg(device));
    dlg.addButtons({ tr("Reboot later"), tr("Reboot now") });
    if (dlg.exec() == 1)
        requestReboot();
}

void EventsHandler::requestReboot()
{
    QDBusInterface sessMng("com.deepin.SessionManager",
                           "/com/deepin/SessionManager",
                           "com.deepin.SessionManager");
    sessMng.asyncCall("RequestReboot");
}

EventsHandler::EventsHandler(QObject *parent)
    : QObject { parent }
{
}
