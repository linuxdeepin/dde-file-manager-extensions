// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "eventshandler.h"
#include "dfmplugin_disk_encrypt_global.h"
#include "gui/encryptprogressdialog.h"
#include "gui/unlockpartitiondialog.h"
#include "gui/encryptparamsinputdialog.h"
#include "utils/encryptutils.h"
#include "menu/diskencryptmenuscene.h"

#include <dfm-framework/dpf.h>
#include <dfm-base/utils/finallyutil.h>

#include <QApplication>
#include <QtConcurrent/QtConcurrent>
#include <QSettings>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusPendingCall>

#include <DDialog>

Q_DECLARE_METATYPE(QString *)
Q_DECLARE_METATYPE(bool *)

using namespace dfmplugin_diskenc;
using namespace disk_encrypt;
DWIDGET_USE_NAMESPACE;

EventsHandler *EventsHandler::instance()
{
    static EventsHandler ins;
    return &ins;
}

void EventsHandler::bindDaemonSignals()
{
    // FIXME(xust) split the unlock module into another plugin.
    // for unlocking devices in file dialog, this plugin is loaded,
    // which cause when en/decrypt devices, the signal are handled
    // by both file manager and file dialog, so multiple progress
    // dialog and finished dialog are shown.
    // this class is singleton but in different process it's not.
    if (qApp->applicationName() != "dde-file-manager")
        return;

    auto conn = [this](const char *sig, const char *slot) {
        QDBusConnection::systemBus().connect(kDaemonBusName,
                                             kDaemonBusPath,
                                             kDaemonBusIface,
                                             sig,
                                             this,
                                             slot);
    };
    conn("PrepareEncryptDiskResult", SLOT(onPreencryptResult(const QString &, const QString &, const QString &, int)));
    conn("EncryptDiskResult", SLOT(onEncryptResult(const QString &, const QString &, int)));
    conn("EncryptProgress", SLOT(onEncryptProgress(const QString &, const QString &, double)));
    conn("DecryptDiskResult", SLOT(onDecryptResult(const QString &, const QString &, const QString &, int)));
    conn("DecryptProgress", SLOT(onDecryptProgress(const QString &, const QString &, double)));
    conn("ChangePassphressResult", SLOT(onChgPassphraseResult(const QString &, const QString &, const QString &, int)));
    conn("RequestEncryptParams", SLOT(onRequestEncryptParams(const QVariantMap &)));
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

bool EventsHandler::isEncrypting(const QString &device)
{
    return encryptDialogs.contains(device) || decryptDialogs.contains(device);
}

void EventsHandler::onPreencryptResult(const QString &dev, const QString &devName, const QString &, int code)
{
    QApplication::restoreOverrideCursor();

    if (code != kSuccess) {
        showPreEncryptError(dev, devName, code);
        return;
    }

    qInfo() << "reboot is required..." << dev;
    showRebootOnPreencrypted(dev, devName);
}

void EventsHandler::onEncryptResult(const QString &dev, const QString &devName, int code)
{
    QApplication::restoreOverrideCursor();
    // if (encryptDialogs.contains(dev)) {
    //     delete encryptDialogs.value(dev);
    //     encryptDialogs.remove(dev);
    // }
    auto dialog = encryptDialogs.take(dev);

    QString device = QString("%1(%2)").arg(devName).arg(dev.mid(5));

    QString title = tr("Encrypt done");
    QString msg = tr("Device %1 has been encrypted").arg(device);
    if (code != 0) {
        title = tr("Encrypt failed");
        msg = tr("Device %1 encrypt failed, please see log for more information.(%2)")
                      .arg(device)
                      .arg(code);
    }

    if (!dialog)
        dialog_utils::showDialog(title, msg, code != 0 ? dialog_utils::kError : dialog_utils::kInfo);
    else {
        auto pos = dialog->geometry().topLeft();
        dialog->showResultPage(code == 0, title, msg);
        dialog->move(pos);
    }

    // delete auto start file.
    auto configPath = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);
    auto autoStartFilePath = configPath + "/autostart/dfm-reencrypt.desktop";
    int ret = ::remove(autoStartFilePath.toStdString().c_str());
    qInfo() << "autostart file has been removed:" << ret;
}

void EventsHandler::onDecryptResult(const QString &dev, const QString &devName, const QString &, int code)
{
    QApplication::restoreOverrideCursor();
    if (code == -kRebootRequired)
        showRebootOnDecrypted(dev, devName);
    else {
        showDecryptError(dev, devName, code);
    }
}

void EventsHandler::onChgPassphraseResult(const QString &dev, const QString &devName, const QString &, int code)
{
    QApplication::restoreOverrideCursor();
    showChgPwdError(dev, devName, code);
}

void EventsHandler::onRequestEncryptParams(const QVariantMap &encConfig)
{
    qApp->restoreOverrideCursor();
    QString devPath = encConfig.value("device-path").toString();
    if (devPath.isEmpty()) {
        qWarning() << "invalid encrypt config!" << encConfig;
        return;
    }

    if (encryptInputs.value(devPath, nullptr))
        return;

    disk_encrypt::DeviceEncryptParam param;
    param.devDesc = devPath;
    param.initOnly = false;
    param.clearDevUUID = encConfig.value("device").toString().remove("UUID=");
    QString objPath = "/org/freedesktop/UDisks2/block_devices/" + devPath.mid(5);
    auto blkDev = device_utils::createBlockDevice(objPath);
    param.backingDevUUID = blkDev ? blkDev->getProperty(dfmmount::Property::kBlockIDUUID).toString() : "";
    param.deviceDisplayName = encConfig.value("device-name").toString();
    auto dlg = new EncryptParamsInputDialog(param, qApp->activeWindow());
    encryptInputs.insert(devPath, dlg);

    int ret = dlg->exec();
    if (ret != QDialog::Accepted) {
        delete encryptInputs.take(devPath);
        return;
    }
    param = dlg->getInputs();
    DiskEncryptMenuScene::doReencryptDevice(param);
}

void EventsHandler::onEncryptProgress(const QString &dev, const QString &devName, double progress)
{
    if (!encryptDialogs.contains(dev)) {
        QString device = QString("%1(%2)").arg(devName).arg(dev.mid(5));

        QApplication::restoreOverrideCursor();
        auto dlg = new EncryptProgressDialog(qApp->activeWindow());
        dlg->setText(tr("%1 is under encrypting...").arg(device),
                     tr("The encrypting process may have system lag, please minimize the system operation"));
        encryptDialogs.insert(dev, dlg);
    }
    auto dlg = encryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();

    // when start encrypt, delete the inputs widget.
    if (encryptInputs.contains(dev))
        delete encryptInputs.take(dev);
}

void EventsHandler::onDecryptProgress(const QString &dev, const QString &devName, double progress)
{
    if (!decryptDialogs.contains(dev)) {
        QString device = QString("%1(%2)").arg(devName).arg(dev.mid(5));

        QApplication::restoreOverrideCursor();
        auto dlg = new EncryptProgressDialog(qApp->activeWindow());
        dlg->setText(tr("%1 is under decrypting...").arg(device),
                     tr("The decrypting process may have system lag, please minimize the system operation"));
        decryptDialogs.insert(dev, dlg);
    }

    auto dlg = decryptDialogs.value(dev);
    dlg->updateProgress(progress);
    dlg->show();
}

bool EventsHandler::onAcquireDevicePwd(const QString &dev, QString *pwd, bool *cancelled)
{
    if (!pwd || !cancelled)
        return false;

    if (EventsHandler::instance()->isEncrypting(dev)) {
        *cancelled = true;
        return true;
    }

    int type = device_utils::encKeyType(dev);

    // test tpm
    bool testTPM = (type == kTPMAndPIN || type == kTPMOnly);
    if (testTPM && tpm_utils::checkTPM() != 0) {
        qWarning() << "TPM service is not available.";
        int ret = dialog_utils::showDialog(tr("Error"), tr("TPM status is abnormal, please use the recovery key to unlock it"),
                                           dialog_utils::DialogType::kError);
        // unlock by recovery key.
        if (ret == 0)
            *pwd = acquirePassphraseByRec(dev, *cancelled);

        return true;
    }

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

QString EventsHandler::acquirePassphraseByRec(const QString &dev, bool &cancelled)
{
    UnlockPartitionDialog dlg(UnlockPartitionDialog::kRec);
    int ret = dlg.exec();
    if (ret != 1) {
        cancelled = true;
        return "";
    }
    auto keys = dlg.getUnlockKey();
    return keys.second;
}

void EventsHandler::showPreEncryptError(const QString &dev, const QString &devName, int code)
{
    QString title;
    QString msg;
    QString device = QString("%1(%2)").arg(devName).arg(dev.mid(5));

    bool showError = false;
    switch (-code) {
    case (kSuccess):
        title = tr("Preencrypt done");
        msg = tr("Device %1 has been preencrypt, please reboot to finish encryption.")
                      .arg(device);
        break;
    case kUserCancelled:
        title = tr("Encrypt disk");
        msg = tr("User cancelled operation");
        break;
    default:
        title = tr("Preencrypt failed");
        msg = tr("Device %1 preencrypt failed, please see log for more information.(%2)")
                      .arg(device)
                      .arg(code);
        showError = true;
        break;
    }

    dialog_utils::showDialog(title, msg,
                             showError ? dialog_utils::kError : dialog_utils::kInfo);
}

void EventsHandler::showDecryptError(const QString &dev, const QString &devName, int code)
{
    QString title;
    QString msg;
    QString device = QString("%1(%2)").arg(devName).arg(dev.mid(5));

    bool showFailed = true;
    switch (-code) {
    case (kSuccess):
        title = tr("Decrypt done");
        msg = tr("Device %1 has been decrypted").arg(device);
        showFailed = false;
        break;
    case kUserCancelled:
        title = tr("Decrypt disk");
        msg = tr("User cancelled operation");
        showFailed = false;
        break;
    case kErrorWrongPassphrase:
        title = tr("Decrypt disk");
        msg = tr("Wrong passpharse or PIN");
        break;
    case kErrorNotFullyEncrypted:
        title = tr("Decrypt failed");
        msg = tr("Device %1 is under encrypting, please decrypt after encryption finished.")
                      .arg(device);
        break;
    default:
        title = tr("Decrypt failed");
        msg = tr("Device %1 Decrypt failed, please see log for more information.(%2)")
                      .arg(device)
                      .arg(code);
        break;
    }

    auto dialog = decryptDialogs.take(dev);
    if (dialog) {
        auto pos = dialog->geometry().topLeft();
        dialog->showResultPage(code == 0, title, msg);
        dialog->move(pos);
    } else {
        dialog_utils::showDialog(title, msg,
                                 showFailed ? dialog_utils::kError : dialog_utils::kInfo);
    }
}

void EventsHandler::showChgPwdError(const QString &dev, const QString &devName, int code)
{
    QString title;
    QString msg;
    QString device = QString("%1(%2)").arg(devName).arg(dev.mid(5));

    int encType = device_utils::encKeyType(dev);
    QString codeType;
    switch (encType) {
    case SecKeyType::kPasswordOnly:
        codeType = tr("passphrase");
        break;
    default:
        codeType = tr("PIN");
        break;
    }

    bool showError = false;
    switch (-code) {
    case (kSuccess):
        title = tr("Change %1 done").arg(codeType);
        msg = tr("%1's %2 has been changed").arg(device).arg(codeType);
        break;
    case kUserCancelled:
        title = tr("Change %1").arg(codeType);
        msg = tr("User cancelled operation");
        break;
    case kErrorChangePassphraseFailed:
        title = tr("Change %1 failed").arg(codeType);
        msg = tr("Wrong %1").arg(codeType);
        showError = true;
        break;
    default:
        title = tr("Change %1 failed").arg(codeType);
        msg = tr("Device %1 change %2 failed, please see log for more information.(%3)")
                      .arg(device)
                      .arg(codeType)
                      .arg(code);
        showError = true;
        break;
    }

    dialog_utils::showDialog(title, msg,
                             showError ? dialog_utils::kError : dialog_utils::kInfo);
}

void EventsHandler::showRebootOnPreencrypted(const QString &device, const QString &devName)
{
    autoStartDFM();

    QString dev = QString("%1(%2)").arg(devName).arg(device.mid(5));

    DDialog dlg(qApp->activeWindow());
    if (dialog_utils::isWayland())
        dlg.setWindowFlag(Qt::WindowStaysOnTopHint);
    dlg.setIcon(QIcon::fromTheme("dialog-information"));
    dlg.setTitle(tr("Reboot to set up encryption"));
    dlg.setMessage(tr("Partition encryption is being performed on device %1, "
                      "please reboot the system to initialize the encryption environment.")
                           .arg(dev));
    dlg.addButtons({ tr("Reboot later"), tr("Reboot now") });
    if (dlg.exec() == 1)
        requestReboot();
}

void EventsHandler::showRebootOnDecrypted(const QString &device, const QString &devName)
{
    QString dev = QString("%1(%2)").arg(devName).arg(device.mid(5));

    DDialog dlg(qApp->activeWindow());
    if (dialog_utils::isWayland())
        dlg.setWindowFlag(Qt::WindowStaysOnTopHint);
    dlg.setIcon(QIcon::fromTheme("dialog-information"));
    dlg.setTitle(tr("Decrypt device"));
    dlg.setMessage(tr("Please reboot to decrypt device %1.")
                           .arg(dev));
    dlg.addButtons({ tr("Reboot later"), tr("Reboot now") });
    if (dlg.exec() == 1)
        requestReboot();
}

void EventsHandler::requestReboot()
{
    qInfo() << "reboot is confirmed...";
    QDBusInterface sessMng("com.deepin.SessionManager",
                           "/com/deepin/SessionManager",
                           "com.deepin.SessionManager");
    sessMng.asyncCall("RequestReboot");
}

void EventsHandler::autoStartDFM()
{
    qInfo() << "autostart is going to added...";
    QDBusInterface sessMng("com.deepin.SessionManager",
                           "/com/deepin/StartManager",
                           "com.deepin.StartManager");
    sessMng.asyncCall("AddAutostart", QString(kReencryptDesktopFile));
}

EventsHandler::EventsHandler(QObject *parent)
    : QObject { parent }
{
}
