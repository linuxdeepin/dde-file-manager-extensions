// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "encryptworker.h"
#include "diskencrypt.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QDir>
#include <QRegularExpression>
#include <QSettings>

FILE_ENCRYPT_USE_NS
using namespace disk_encrypt;

#define DEV_KEY QString("device/%1")
static constexpr char kBootUsecPath[] { "/boot/usec-crypt" };

void createUsecPathIfNotExist()
{
    QDir d(kBootUsecPath);
    if (!d.exists()) {
        bool ok = d.mkpath(kBootUsecPath);
        qDebug() << kBootUsecPath << " path created: " << ok;
    }
}

PrencryptWorker::PrencryptWorker(const QString &jobID,
                                 const QVariantMap &params,
                                 QObject *parent)
    : Worker(jobID, parent),
      params(params)
{
}

void PrencryptWorker::run()
{
    QString mpt = params.value(encrypt_param_keys::kKeyMountPoint).toString();
    if (kDisabledEncryptPath.contains(mpt, Qt::CaseInsensitive)) {
        qInfo() << "device mounted at disable list, ignore encrypt.";
        setExitCode(-kErrorDisabledMountPoint);
        return;
    }

    if (params.value(encrypt_param_keys::kKeyInitParamsOnly, false).toBool()) {
        setExitCode(writeEncryptParams());
        setFstabTimeout();
        return;
    }

    auto encParams = disk_encrypt_utils::bcConvertParams(params);
    if (!disk_encrypt_utils::bcValidateParams(encParams)) {
        setExitCode(-kErrorParamsInvalid);
        qDebug() << "invalid params" << params;
        return;
    }

    QString localHeaderFile;
    int err = disk_encrypt_funcs::bcInitHeaderFile(encParams,
                                                   localHeaderFile,
                                                   &keyslotCipher,
                                                   &keyslotRecKey);
    if (err != kSuccess || localHeaderFile.isEmpty()) {
        setExitCode(-kErrorCreateHeader);
        qDebug() << "cannot generate local header"
                 << params;
        return;
    }

    int ret = disk_encrypt_funcs::bcInitHeaderDevice(encParams.device,
                                                     encParams.passphrase,
                                                     localHeaderFile);
    if (ret != 0) {
        setExitCode(-kErrorApplyHeader);
        qDebug() << "cannot init device encrypt"
                 << params;
        return;
    }

    if (!encParams.tpmToken.isEmpty()) {
        QFile f(QString(TOKEN_FILE_PATH).arg(encParams.device.mid(5)));
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qWarning() << "cannot open file to cache token";
            return;
        }
        f.write(encParams.tpmToken.toLocal8Bit());
        f.flush();
        f.close();
    }
}

int PrencryptWorker::writeEncryptParams()
{
    const static QMap<int, QString> encMode {
        { 0, "pin" },
        { 1, "tpm-pin" },
        { 2, "tpm" }
    };

    QJsonObject obj;
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    QString dmDev = QString("dm-%1").arg(dev.mid(5));
    QString uuid = QString("UUID=%1").arg(params.value(encrypt_param_keys::kKeyUUID).toString());

    obj.insert("volume", dmDev);   // used to name a opened luks device.
    obj.insert("device", uuid);   // used to locate the backing device.
    obj.insert("device-path", dev);   // used to locate the backing device by device path.
    obj.insert("device-name", params.value(encrypt_param_keys::kKeyDeviceName).toString());   // the device name display in dde-file-manager
    obj.insert("device-mountpoint", params.value(encrypt_param_keys::kKeyMountPoint).toString());   // the mountpoint of the device
    obj.insert("cipher", params.value(encrypt_param_keys::kKeyCipher).toString() + "-xts-plain64");
    obj.insert("key-size", "256");
    obj.insert("mode", encMode.value(params.value(encrypt_param_keys::kKeyEncMode).toInt()));

    QString expPath = params.value(encrypt_param_keys::kKeyRecoveryExportPath).toString();
    if (!expPath.isEmpty()) {
        expPath.append(QString("/recovery_key_%1.txt").arg(dev.mid(5)));
        expPath.replace("//", "/");
    }
    obj.insert("recoverykey-path", expPath);

    QJsonDocument tpmConfig = QJsonDocument::fromJson(params.value(encrypt_param_keys::kKeyTPMConfig).toString().toLocal8Bit());
    obj.insert("tpm-config", tpmConfig.object());   // the tpm info used to decrypt passphrase from tpm.
    QJsonDocument doc(obj);

    createUsecPathIfNotExist();

    QFile f(QString("%1/encrypt.json").arg(kBootUsecPath));
    if (f.exists())
        qInfo() << "has pending job, the pending job will be replaced";

    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open file for write!";
        return -kErrorOpenFileFailed;
    }

    f.write(doc.toJson());
    f.flush();
    f.close();
    return -kSuccess;
}

int PrencryptWorker::setFstabTimeout()
{
    static const QString kFstabPath { "/etc/fstab" };
    QFile fstab(kFstabPath);
    if (!fstab.open(QIODevice::ReadOnly))
        return kErrorOpenFstabFailed;

    QByteArray fstabContents = fstab.readAll();
    fstab.close();

    static const QByteArray kTimeoutParam = "x-systemd.device-timeout=0";
    QString devDesc = params.value(encrypt_param_keys::kKeyDevice).toString();
    QString devUUID = QString("UUID=%1").arg(params.value(encrypt_param_keys::kKeyUUID).toString());
    QByteArrayList fstabLines = fstabContents.split('\n');
    QList<QStringList> fstabItems;
    bool foundItem = false;
    for (const QString &line : fstabLines) {
        QStringList items = line.split(QRegularExpression(R"(\t| )"), QString::SkipEmptyParts);
        if (items.count() == 6
            && (items[0] == devDesc || items[0] == devUUID)
            && !foundItem) {

            if (!items[3].contains(kTimeoutParam)) {
                items[3] += ("," + kTimeoutParam);
                foundItem = true;
            }
        }
        fstabItems.append(items);
    }

    if (foundItem) {
        QByteArray newContents;
        for (const auto &items : fstabItems) {
            newContents += items.join('\t');
            newContents.append('\n');
        }

        if (!fstab.open(QIODevice::Truncate | QIODevice::ReadWrite))
            return kErrorOpenFstabFailed;

        fstab.write(newContents);
        fstab.flush();
        fstab.close();

        qDebug() << "old fstab contents:"
                 << fstabContents;
        qDebug() << "new fstab contents"
                 << newContents;
    }

    return kSuccess;
}

ReencryptWorker::ReencryptWorker(const QString &dev,
                                 const QString &passphrase,
                                 QObject *parent)
    : Worker("", parent),
      passphrase(passphrase),
      device(dev)
{
}

void ReencryptWorker::run()
{
    int ret = disk_encrypt_funcs::bcResumeReencrypt(device,
                                                    passphrase);

    Q_EMIT deviceReencryptResult(device, ret);
}

DecryptWorker::DecryptWorker(const QString &jobID,
                             const QVariantMap &params,
                             QObject *parent)
    : Worker(jobID, parent),
      params(params)
{
}

void DecryptWorker::run()
{
    bool initOnly = params.value(encrypt_param_keys::kKeyInitParamsOnly).toBool();
    if (initOnly) {
        setExitCode(writeDecryptParams());
        return;
    }

    const QString &device = params.value(encrypt_param_keys::kKeyDevice).toString();
    const QString &passphrase = params.value(encrypt_param_keys::kKeyPassphrase).toString();
    int ret = disk_encrypt_funcs::bcDecryptDevice(device, passphrase);
    if (ret < 0) {
        setExitCode(ret);
        qDebug() << "decrypt devcei failed"
                 << device
                 << ret;
        return;
    }
}

int DecryptWorker::writeDecryptParams()
{
    QJsonObject obj;
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    obj.insert("device-path", dev);
    QString uuid = QString("UUID=%1").arg(params.value(encrypt_param_keys::kKeyUUID).toString());
    obj.insert("device", uuid);
    QJsonDocument doc(obj);

    createUsecPathIfNotExist();

    QFile f(QString("%1/decrypt.json").arg(kBootUsecPath));
    if (f.exists())
        qInfo() << "the decrypt task will be replaced";
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open decrypt file for writing";
        return -kErrorOpenFileFailed;
    }

    f.write(doc.toJson());
    f.close();
    return -kRebootRequired;
}

ChgPassWorker::ChgPassWorker(const QString &jobID, const QVariantMap &params, QObject *parent)
    : Worker(jobID, parent),
      params(params)
{
}

void ChgPassWorker::run()
{
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    QString oldPass = params.value(encrypt_param_keys::kKeyOldPassphrase).toString();
    QString newPass = params.value(encrypt_param_keys::kKeyPassphrase).toString();

    int newSlot = 0;
    int ret = 0;
    if (params.value(encrypt_param_keys::kKeyValidateWithRecKey, false).toBool())
        ret = disk_encrypt_funcs::bcChangePassphraseByRecKey(dev, oldPass, newPass, &newSlot);
    else
        ret = disk_encrypt_funcs::bcChangePassphrase(dev, oldPass, newPass, &newSlot);

    QString token = params.value(encrypt_param_keys::kKeyTPMToken).toString();
    if (!token.isEmpty() && ret == 0) {
        // The value in keyslots represents the keyslot location where the passphrase is located
        QJsonDocument doc = QJsonDocument::fromJson(token.toLocal8Bit());
        QJsonObject obj = doc.object();
        obj.insert("keyslots", QJsonArray::fromStringList({ QString::number(newSlot) }));
        doc.setObject(obj);
        token = doc.toJson(QJsonDocument::Compact);

        ret = disk_encrypt_funcs::bcSetToken(dev, token);
        if (ret != 0)   // update token failed, need to rollback the change.
            disk_encrypt_funcs::bcChangePassphrase(dev, newPass, oldPass, &newSlot);
    }

    setExitCode(ret);
}
