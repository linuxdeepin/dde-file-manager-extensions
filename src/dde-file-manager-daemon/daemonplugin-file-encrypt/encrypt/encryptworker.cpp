// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "encryptworker.h"
#include "diskencrypt.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QDir>
#include <QRegularExpression>
#include <QSettings>

FILE_ENCRYPT_USE_NS

#define DEV_ENCTYPE_CFG "/etc/deepin/dde-file-manager/dev_enc_type.ini"
#define DEV_KEY QString("device/%1")

PrencryptWorker::PrencryptWorker(const QString &jobID,
                                 const QVariantMap &params,
                                 QObject *parent)
    : Worker(jobID, parent),
      params(params)
{
}

void PrencryptWorker::run()
{
    auto recoredSets = [](const QString &k, int v) {
        QSettings sets(DEV_ENCTYPE_CFG, QSettings::IniFormat);
        sets.setValue(DEV_KEY.arg(k.mid(5)), v);
    };

    if (params.value(encrypt_param_keys::kKeyInitParamsOnly, false).toBool()) {
        auto code = writeEncryptParams();
        setExitCode(code);
        setFstabTimeout();

        if (code == EncryptJobError::kNoError)
            recoredSets(params.value(encrypt_param_keys::kKeyDevice).toString(),
                        params.value(encrypt_param_keys::kKeyEncMode).toInt());
        return;
    }

    auto encParams = disk_encrypt_utils::bcConvertParams(params);
    if (!disk_encrypt_utils::bcValidateParams(encParams)) {
        setExitCode(EncryptJobError::kInvalidEncryptParams);
        qDebug() << "invalid params" << params;
        return;
    }

    QString localHeaderFile;
    EncryptError err = disk_encrypt_funcs::bcInitHeaderFile(encParams,
                                                            localHeaderFile);
    if (err != EncryptError::kNoError || localHeaderFile.isEmpty()) {
        setExitCode(EncryptJobError::kCannotInitEncryptHeaderFile);
        qDebug() << "cannot generate local header"
                 << params;
        return;
    }

    int ret = disk_encrypt_funcs::bcInitHeaderDevice(encParams.device,
                                                     encParams.passphrase,
                                                     localHeaderFile);
    if (ret != 0) {
        setExitCode(EncryptJobError::kCannotInitEncryptHeaderDevice);
        qDebug() << "cannot init device encrypt"
                 << params;
        return;
    }

    recoredSets(params.value(encrypt_param_keys::kKeyDevice).toString(),
                params.value(encrypt_param_keys::kKeyEncMode).toInt());
}

EncryptJobError PrencryptWorker::writeEncryptParams()
{
    const static QMap<int, QString> encMode {
        { 0, "pin" },
        { 1, "tpm-pin" },
        { 2, "tpm" }
    };

    QJsonObject obj;
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    QString dmDev = QString("dm-%1").arg(dev.mid(5));
    obj.insert("device", dev);
    obj.insert("volume", dmDev);
    obj.insert("cipher", params.value(encrypt_param_keys::kKeyCipher).toString());
    obj.insert("key-size", "256");
    obj.insert("mode", encMode.value(params.value(encrypt_param_keys::kKeyEncMode).toInt()));
    obj.insert("recoverykey-path", params.value(encrypt_param_keys::kKeyRecoveryExportPath).toString());

    QJsonDocument tpmConfig = QJsonDocument::fromJson(params.value(encrypt_param_keys::kKeyTPMConfig).toString().toLocal8Bit());
    obj.insert("tpm-config", tpmConfig.object());

    QJsonDocument doc(obj);
    QString encFilePath = "/boot/usec-crypt";
    QDir d;
    d.mkdir(encFilePath);

    QString fname = dev.replace("/", "_");   // maybe someday multi job supported
    fname = "encrypt.json";   // but now, keeps only one encrypt task.
    QFile f(encFilePath + "/" + fname);

    if (f.exists()) {
        qInfo() << "has pending job, the pending job will be replaced";
        //        return EncryptJobError::kHasPendingEncryptJob;
    }

    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open file for write!";
        return EncryptJobError::kCannotCreateEncryptJob;
    }

    f.write(doc.toJson());
    f.flush();
    f.close();
    return EncryptJobError::kNoError;
}

EncryptJobError PrencryptWorker::setFstabTimeout()
{
    static const QString kFstabPath { "/etc/fstab" };
    QFile fstab(kFstabPath);
    if (!fstab.open(QIODevice::ReadOnly))
        return EncryptJobError::kFstabOpenFailed;

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
            return EncryptJobError::kFstabOpenFailed;

        fstab.write(newContents);
        fstab.flush();
        fstab.close();

        qDebug() << "old fstab contents:"
                 << fstabContents;
        qDebug() << "new fstab contents"
                 << newContents;
    }

    return EncryptJobError::kNoError;
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
    auto removeSets = [](const QString &k) {
        QSettings sets(DEV_ENCTYPE_CFG, QSettings::IniFormat);
        sets.remove(DEV_KEY.arg(k.mid(5)));
    };

    bool initOnly = params.value(encrypt_param_keys::kKeyInitParamsOnly).toBool();
    if (initOnly) {
        setExitCode(writeDecryptParams());
        return;
    }

    const QString &device = params.value(encrypt_param_keys::kKeyDevice).toString();
    const QString &passphrase = params.value(encrypt_param_keys::kKeyPassphrase).toString();
    int ret = disk_encrypt_funcs::bcDecryptDevice(device, passphrase);
    if (ret < 0) {
        setExitCode(EncryptJobError::kDecryptFailed);
        qDebug() << "decrypt devcei failed"
                 << device
                 << ret;
        return;
    }
    removeSets(device);
}

EncryptJobError DecryptWorker::writeDecryptParams()
{
    return EncryptJobError::kNoError;
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

    int ret = 0;
    if (params.value(encrypt_param_keys::kKeyValidateWithRecKey, false).toBool())
        ret = disk_encrypt_funcs::bcChangePassphraseByRecKey(dev, oldPass, newPass);
    else
        ret = disk_encrypt_funcs::bcChangePassphrase(dev, oldPass, newPass);
    setExitCode(ret < 0 ? EncryptJobError::kChgPassphraseFailed : EncryptJobError::kNoError);
}
