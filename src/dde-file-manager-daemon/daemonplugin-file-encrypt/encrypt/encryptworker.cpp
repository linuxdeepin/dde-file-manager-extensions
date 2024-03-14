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
#include <QReadWriteLock>
#include <QTime>

FILE_ENCRYPT_USE_NS
using namespace disk_encrypt;

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
        createReencryptDesktop();
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

    writeEncryptParams(encParams.device);

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

int PrencryptWorker::writeEncryptParams(const QString &device)
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

    QString configPath = QString("%1/encrypt.json").arg(kBootUsecPath);
    if (!device.isEmpty()) {
        configPath = QString("%1/encrypt_%2.json").arg(kBootUsecPath).arg(device.mid(5));
    }

    QFile f(configPath);
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

// this is used to create a desktop file into
// /usr/share/applications/dfm-reencrypt.desktop
void PrencryptWorker::createReencryptDesktop()
{
    QFile f(kReencryptDesktopFile);
    if (f.exists())
        return;

    QByteArray desktop {
        "[Desktop Entry]\n"
        "Categories=System;\n"
        "Comment=To auto launch reencryption\n"
        "Exec=/usr/bin/dde-file-manager -d\n"
        "GenericName=Disk Reencrypt\n"
        "Icon=dde-file-manager\n"
        "Name=Disk Reencrypt\n"
        "Terminal=false\n"
        "Type=Application\n"
        "NoDisplay=true\n"
        "X-AppStream-Ignore=true\n"
        "X-Deepin-AppID=dde-file-manager\n"
        "X-Deepin-Vendor=deepin\n"
    };

    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open desktop file to write!";
        return;
    }
    f.write(desktop);
    f.close();

    qInfo() << "desktop file created.";
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
    const QString &device = params.value(encrypt_param_keys::kKeyDevice).toString();
    EncryptStates status;
    int ret = block_device_utils::bcDevEncryptStatus(device, &status);
    if (ret != kSuccess) {
        qWarning() << "check device status failed!";
        setExitCode(ret);
        return;
    }

    bool isOnlineEncrypting = (status & kStatusOnline) && (status & kStatusEncrypt);
    if (isOnlineEncrypting) {
        qWarning() << "encrypt status not finished, cannot decrypt!" << status << device;
        setExitCode(-kErrorNotFullyEncrypted);
        return;
    }

    bool initOnly = params.value(encrypt_param_keys::kKeyInitParamsOnly).toBool();
    if (initOnly) {
        setExitCode(writeDecryptParams());
        return;
    }

    const QString &passphrase = params.value(encrypt_param_keys::kKeyPassphrase).toString();
    ret = disk_encrypt_funcs::bcDecryptDevice(device, passphrase);
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

ReencryptWorkerV2::ReencryptWorkerV2(QObject *parent)
    : Worker("", parent)
{
}

void ReencryptWorkerV2::setEncryptParams(const QVariantMap &params)
{
    QWriteLocker lk(&lockParam);
    this->params = params;
}

void ReencryptWorkerV2::loadReencryptConfig(const QString &device)
{
    disk_encrypt_utils::bcReadEncryptConfig(&config, device);
}

EncryptConfig ReencryptWorkerV2::encryptConfig() const
{
    return config;
}

void ReencryptWorkerV2::ignoreParamRequest()
{
    QWriteLocker locker(&lockRequest);
    ignoreRequest = true;
    qInfo() << "ignore param request.";
}

void ReencryptWorkerV2::run()
{
    if (!hasUnfinishedOnlineEncryption()) {
        qInfo() << "no unfinished encryption job exists. exit thread.";
        return;
    }

    QString clearDev;
    // found unfinished encrypt job, disable recovery.
    if (config.configPath.endsWith("encrypt.json")) {
        disableABRecovery();
        clearDev = config.clearDev;
    }

    if (waitForInput() == kIgnoreRequest) {
        setExitCode(-kIgnoreRequest);
        return;
    }

    // this open action here is for repairing the reencrypt process.
    int ret = disk_encrypt_funcs::bcOpenDevice(config.devicePath, config.clearDev);
    if (ret != kSuccess) {
        qWarning() << "cannot open device for reencryption!" << ret;
        Q_EMIT deviceReencryptResult(config.devicePath, ret, "");
        return;
    }

    QString msg;
    ret = disk_encrypt_funcs::bcResumeReencrypt(config.devicePath, "", clearDev, false);
    if (ret == kSuccess) {
        // sets the passphrase, token, recovery-key
        setPassphrase();
        setBakcingDevLabel();
        updateCrypttab();
        removeEncryptFile();
        QString recKey;
        bool expKey;
        setRecoveryKey(&recKey, &expKey);
        if (expKey && !recKey.isEmpty()) {
            if (!disk_encrypt_utils::bcSaveRecoveryKey(config.devicePath,
                                                       recKey,
                                                       params.value(encrypt_param_keys::kKeyRecoveryExportPath).toString())) {
                ret = -KErrorRequestExportRecKey;
                msg = recKey;
            }
        }
    } else {
        setExitCode(ret);
    }
    Q_EMIT deviceReencryptResult(config.devicePath, ret, msg);
}

bool ReencryptWorkerV2::hasUnfinishedOnlineEncryption()
{
    if (config.devicePath.isEmpty()) {
        qInfo() << "no unfinished encrypt device.";
        return false;
    }

    // 2. check if it's really unfinished.
    EncryptStates status;
    if (kSuccess != block_device_utils::bcDevEncryptStatus(config.devicePath, &status)) {
        qWarning() << "cannot get encrypt requirements!" << config.devicePath;
        return false;
    }

    if ((status & kStatusOnline)
        && (status & kStatusEncrypt)) {
        // 3. start a worker if device is not finished ONLINE encryption.
        qInfo() << "device is not finished ONLINE encryption:" << config.devicePath;
        return true;
    }
    return false;
}

void ReencryptWorkerV2::setPassphrase()
{
    const QString &pass = params.value(encrypt_param_keys::kKeyPassphrase).toString();
    const QString &token = params.value(encrypt_param_keys::kKeyTPMToken).toString();
    int passKeyslot = -1;
    int ret = disk_encrypt_funcs::bcChangePassphrase(config.devicePath, "", pass, &passKeyslot);
    if (ret != kSuccess) {
        qCritical() << "cannot set passphrase for device!" << config.devicePath << ret;
        setExitCode(ret);
        return;
    }

    if (!token.isEmpty()) {
        // update token keyslot.
        auto _token = updateTokenKeyslots(token, passKeyslot);
        ret = disk_encrypt_funcs::bcSetToken(config.devicePath, _token);
        if (ret != kSuccess) {
            qCritical() << "cannot set token for device!" << config.devicePath << ret;
            setExitCode(ret);
            return;
        }
    }

    qInfo() << "passphrase has been setted at keyslot:" << passKeyslot;
}

void ReencryptWorkerV2::setRecoveryKey(QString *key, bool *expKey)
{
    Q_ASSERT(key && expKey);
    *expKey = false;
    const QString &recPath = params.value(encrypt_param_keys::kKeyRecoveryExportPath).toString();
    if (recPath.isEmpty())
        return;

    *key = disk_encrypt_utils::bcGenRecKey();
    if (key->isEmpty()) {
        qWarning() << "generate recovery key failed!";
        return;
    }

    int recKeySlot = -1;
    const QString &pass = params.value(encrypt_param_keys::kKeyPassphrase).toString();
    int ret = disk_encrypt_funcs::bcChangePassphraseByRecKey(config.devicePath, pass, *key, &recKeySlot);
    if (ret != kSuccess) {
        qCritical() << "cannot set recovery key for device!" << config.devicePath << ret;
        setExitCode(ret);
        return;
    }
    *expKey = true;

    QString recToken = QString("{ 'type': 'usec-recoverykey', 'keyslots': ['%1'] }").arg(recKeySlot);
    ret = disk_encrypt_funcs::bcSetToken(config.devicePath, recToken);
    if (ret != kSuccess) {
        qCritical() << "cannot set recovery token for device!" << config.devicePath << ret;
        setExitCode(ret);
        return;
    }
    qInfo() << "recovery key has been setted at keyslot:" << recKeySlot;
}

void ReencryptWorkerV2::setBakcingDevLabel()
{
    int ret = disk_encrypt_funcs::bcSetLabel(config.devicePath, config.deviceName);
    if (ret != kSuccess)
        qWarning() << "set label to device failed:" << config.devicePath << config.deviceName << ret;
    qInfo() << "device name setted." << config.devicePath << config.deviceName;
}

void ReencryptWorkerV2::updateCrypttab()
{
    qInfo() << "start updating crypttab...";

    QString tpmToken = params.value(encrypt_param_keys::kKeyTPMToken).toString();
    if (tpmToken.isEmpty())
        return;

    // do update crypttab item, append tpm info: tpm2-device=auto
    QFile crypttab("/etc/crypttab");
    if (!crypttab.open(QIODevice::ReadOnly)) {
        qWarning() << "cannot open crypttab for reading";
        return;
    }
    auto contents = crypttab.readAll();
    crypttab.close();

    bool crypttabUpdated = false;
    QString srcDev = QString("UUID=") + params.value(encrypt_param_keys::kKeyBackingDevUUID).toString();
    QByteArrayList lines = contents.split('\n');
    for (auto &line : lines) {
        QString _line = line;
        if (_line.contains(srcDev)) {
            if (!_line.contains("tpm2-device=auto")) {
                _line.append(",tpm2-device=auto");
                line = _line.toLocal8Bit();
                crypttabUpdated = true;
            }
            break;
        }
    }
    if (!crypttabUpdated) {
        qInfo() << "no need to update crypttab.";
        return;
    }

    contents = lines.join('\n');

    if (!crypttab.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open crypttab for writing";
        return;
    }
    crypttab.write(contents.data());
    crypttab.close();
    qInfo() << "crypttab has been updated:\n"
            << contents;
}

void ReencryptWorkerV2::removeEncryptFile()
{
    int ret = ::remove(config.configPath.toStdString().c_str());
    qInfo() << "encrypt job file has been removed." << ret
            << config.configPath;
}

QString ReencryptWorkerV2::updateTokenKeyslots(const QString &token, int keyslot)
{
    QJsonDocument doc = QJsonDocument::fromJson(token.toLocal8Bit());
    auto obj = doc.object();
    obj.insert("keyslots", QJsonArray::fromStringList({ QString::number(keyslot) }));
    doc.setObject(obj);
    return doc.toJson(QJsonDocument::Compact);
}

bool ReencryptWorkerV2::validateParams()
{
    if (params.isEmpty())
        return false;

    if (params.value(encrypt_param_keys::kKeyDevice).toString() != config.devicePath)
        return false;

    if (params.value(encrypt_param_keys::kKeyPassphrase).toString().isEmpty())
        return false;

    return true;
}

void ReencryptWorkerV2::disableABRecovery()
{
    QFile cfg("/etc/default/grub.d/13_deepin_ab_recovery.cfg");
    QByteArray cfgContents;
    if (cfg.exists()) {
        if (!cfg.open(QIODevice::ReadOnly)) {
            qWarning() << "cannot open recovery config!";
            return;
        }
        cfgContents = cfg.readAll();
        cfg.close();
    }

    QByteArrayList lines = cfgContents.split('\n');
    for (int i = 0; i < lines.count(); ++i) {
        QString line = lines.at(i);
        if (line.startsWith("#"))
            continue;

        if (line.contains("DISABLE_AB_ROLLBACK")) {
            if (line.contains("export DISABLE_AB_ROLLBACK=true")) {
                qInfo() << "rollback already disabled.";
                return;
            }

            lines.removeAt(i);
            break;
        }
    }
    lines.append("export DISABLE_AB_ROLLBACK=true\n");
    cfgContents = lines.join('\n');

    qDebug() << "the ab recovery contents:\n"
             << cfgContents;

    if (!cfg.open(QIODevice::Truncate | QIODevice::WriteOnly)) {
        qWarning() << "cannot open recovery config to write!";
        return;
    }
    cfg.write(cfgContents);
    cfg.close();

    // update grub
    auto fd = utils::inhibit();
    qInfo() << "blocking reboot:" << fd.value().fileDescriptor();
    QTime t;
    t.start();
    int ret = system("update-grub");
    qInfo() << "update grub costs" << t.elapsed() << "ms and result is" << ret;
}

int ReencryptWorkerV2::waitForInput()
{
    while (true) {
        {
            QReadLocker lk(&lockParam);
            if (validateParams())
                break;
        }
        {
            QReadLocker lk(&lockRequest);
            if (ignoreRequest)
                return kIgnoreRequest;
        }

        Q_EMIT requestEncryptParams(config.keyConfig());
        QThread::sleep(3);   // don't request frequently.
    }
    return kSuccess;
}
