// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptutils.h"
#include "dfmplugin_disk_encrypt_global.h"

#include <dfm-framework/event/event.h>

#include <dfm-mount/dmount.h>

#include <QSettings>

#include <dconfig.h>
#include <DDialog>

#include <fstab.h>

Q_DECLARE_METATYPE(bool *)
Q_DECLARE_METATYPE(QString *)

#define DEV_ENCTYPE_CFG "/etc/deepin/dde-file-manager/dev_enc_type.ini"
#define DEV_KEY QString("device/%1")

using namespace dfmplugin_diskenc;

bool config_utils::exportKeyEnabled()
{
    auto cfg = Dtk::Core::DConfig::create("org.deepin.dde.file-manager",
                                          "org.deepin.dde.file-manager.diskencrypt");
    cfg->deleteLater();
    return cfg->value("allowExportEncKey", true).toBool();
}

QString config_utils::cipherType()
{
    auto cfg = Dtk::Core::DConfig::create("org.deepin.dde.file-manager",
                                          "org.deepin.dde.file-manager.diskencrypt");
    cfg->deleteLater();
    return cfg->value("encryptAlgorithm", "sm4").toString();
}

bool fstab_utils::isFstabItem(const QString &mpt)
{
    if (mpt.isEmpty())
        return false;

    bool fstabed { false };
    struct fstab *fs;
    setfsent();
    while ((fs = getfsent()) != nullptr) {
        QString path = fs->fs_file;
        if (mpt == path) {
            fstabed = true;
            break;
        }
    }
    endfsent();
    return fstabed;
}

bool tpm_utils::hasTPM()
{
    return dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_TPMIsAvailablePro").toBool();
}

bool tpm_utils::getRandomByTPM(int size, QString *output)
{
    return dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_GetRandomByTPMPro", size, output).toBool();
}

bool tpm_utils::isSupportAlgoByTPM(const QString &algoName, bool *support)
{
    return dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_IsTPMSupportAlgoPro", algoName, support).toBool();
}

bool tpm_utils::encryptByTPM(const QVariantMap &map)
{
    return dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_EncryptByTPMPro", map).toBool();
}

bool tpm_utils::decryptByTPM(const QVariantMap &map, QString *psw)
{
    return dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_DecryptByTPMPro", map, psw).toBool();
}

int device_utils::encKeyType(const QString &dev)
{
    QSettings sets(DEV_ENCTYPE_CFG, QSettings::IniFormat);
    int type = sets.value(DEV_KEY.arg(dev.mid(5)), -1).toInt();
    return type;
}

QString tpm_passphrase_utils::genPassphraseFromTPM(const QString &dev, const QString &pin)
{
    QString passphrase;
    if (!tpm_utils::getRandomByTPM(kPasswordSize, &passphrase)
        || passphrase.isEmpty()) {
        qCritical() << "TPM get random number failed!";
        return "";
    }

    const QString dirPath = kTPMKeyPath + dev;
    QDir dir(dirPath);
    if (!dir.exists())
        dir.mkpath(dirPath);

    QString hashAlgo, keyAlgo;
    if (!getAlgorithm(hashAlgo, keyAlgo)) {
        qCritical() << "TPM algo choice failed!";
        return "";
    }

    QVariantMap map {
        { "PropertyKey_PrimaryHashAlgo", hashAlgo },
        { "PropertyKey_PrimaryKeyAlgo", keyAlgo },
        { "PropertyKey_MinorHashAlgo", hashAlgo },
        { "PropertyKey_MinorKeyAlgo", keyAlgo },
        { "PropertyKey_DirPath", dirPath },
        { "PropertyKey_Plain", passphrase },
    };
    if (pin.isEmpty()) {
        map.insert("PropertyKey_EncryptType", kUseTpmAndPcr);
        map.insert("PropertyKey_Pcr", "7");
        map.insert("PropertyKey_PcrBank", hashAlgo);
    } else {
        map.insert("PropertyKey_EncryptType", kUseTpmAndPin);
        map.insert("PropertyKey_PinCode", pin);
    }

    if (!tpm_utils::encryptByTPM(map)) {
        qCritical() << "save to TPM failed!!!";
        return "";
    }

    QSettings settings(dirPath + QDir::separator() + "algo.ini", QSettings::IniFormat);
    settings.setValue(kConfigKeyPriHashAlgo, QVariant(hashAlgo));
    settings.setValue(kConfigKeyPriKeyAlgo, QVariant(keyAlgo));

    qInfo() << "DEBUG INFORMATION>>>>>>>>>>>>>>>   create TPM pwd for device:"
            << dev
            << passphrase;
    return passphrase;
}

QString tpm_passphrase_utils::getPassphraseFromTPM(const QString &dev, const QString &pin)
{
    const QString dirPath = kTPMKeyPath + dev;
    QSettings tpmSets(dirPath + QDir::separator() + "algo.ini", QSettings::IniFormat);
    const QString hashAlgo = tpmSets.value(kConfigKeyPriHashAlgo).toString();
    const QString keyAlgo = tpmSets.value(kConfigKeyPriKeyAlgo).toString();
    QVariantMap map {
        { "PropertyKey_EncryptType", pin.isEmpty() ? kUseTpmAndPcr : kUseTpmAndPin },
        { "PropertyKey_PrimaryHashAlgo", hashAlgo },
        { "PropertyKey_PrimaryKeyAlgo", keyAlgo },
        { "PropertyKey_DirPath", dirPath }
    };

    if (pin.isEmpty()) {
        map.insert("PropertyKey_Pcr", "7");
        map.insert("PropertyKey_PcrBank", hashAlgo);
    } else {
        map.insert("PropertyKey_PinCode", pin);
    }

    QString passphrase;
    bool ok = tpm_utils::decryptByTPM(map, &passphrase);
    if (!ok) {
        qWarning() << "cannot acquire passphrase from TPM for device"
                   << dev;
    }

    qInfo() << "DEBUG INFORMATION>>>>>>>>>>>>>>> got passphrase from TPM of device"
            << dev
            << pin
            << passphrase;
    return passphrase;
}

bool tpm_passphrase_utils::getAlgorithm(QString &hash, QString &key)
{
    bool re1 { false };
    bool re2 { false };
    tpm_utils::isSupportAlgoByTPM(kTPMHashAlgo, &re1);
    tpm_utils::isSupportAlgoByTPM(kTPMKeyAlgo, &re2);

    if (re1 && re2) {
        hash = kTPMHashAlgo;
        key = kTPMKeyAlgo;
        return true;
    }

    re1 = false;
    re2 = false;
    tpm_utils::isSupportAlgoByTPM(kTCMHashAlgo, &re1);
    tpm_utils::isSupportAlgoByTPM(kTCMKeyAlgo, &re2);

    if (re1 && re2) {
        hash = kTCMHashAlgo;
        key = kTCMKeyAlgo;
        return true;
    }

    return false;
}

QString recovery_key_utils::formatRecoveryKey(const QString &raw)
{
    static const int kSectionLen = 6;
    QString formatted = raw;
    formatted.remove("-");
    int len = formatted.length();
    if (len > 24)
        formatted = formatted.mid(0, 24);

    len = formatted.length();
    int dashCount = len / kSectionLen;
    if (len % kSectionLen == 0)
        dashCount -= 1;
    for (; dashCount > 0; dashCount--)
        formatted.insert(dashCount * kSectionLen, '-');
    return formatted;
}

void dialog_utils::showError(const QString &title, const QString &msg)
{
    Dtk::Widget::DDialog d;
    d.setTitle(title);
    d.setMessage(msg);
    d.setIcon(QIcon::fromTheme("dialog-error"));
    d.addButton(qApp->translate("dfmplugin_diskenc::ChgPassphraseDialog", "Confirm"));
    d.exec();
}

BlockDev device_utils::createBlockDevice(const QString &devObjPath)
{
    using namespace dfmmount;
    auto monitor = DDeviceManager::instance()->getRegisteredMonitor(DeviceType::kBlockDevice).objectCast<DBlockMonitor>();
    Q_ASSERT(monitor);
    return monitor->createDeviceById(devObjPath).objectCast<DBlockDevice>();
}

void dialog_utils::showInfo(const QString &title, const QString &msg)
{
    Dtk::Widget::DDialog d;
    d.setTitle(title);
    d.setMessage(msg);
    d.setIcon(QIcon::fromTheme("dialog-info"));
    d.addButton(qApp->translate("dfmplugin_diskenc::ChgPassphraseDialog", "Confirm"));
    d.exec();
}
