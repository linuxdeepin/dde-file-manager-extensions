// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "diskencryptdbus.h"
#include "diskencryptdbus_adaptor.h"
#include "encrypt/encryptworker.h"
#include "encrypt/diskencrypt.h"
#include "notification/notifications.h"

#include <dfm-framework/dpf.h>
#include <dfm-mount/dmount.h>

#include <QtConcurrent>
#include <QDateTime>
#include <QDir>
#include <QDebug>

#include <libcryptsetup.h>

FILE_ENCRYPT_USE_NS
using namespace disk_encrypt;

#define JOB_ID QString("job_%1")
static constexpr char kActionEncrypt[] { "com.deepin.filemanager.daemon.DiskEncrypt.Encrypt" };
static constexpr char kActionDecrypt[] { "com.deepin.filemanager.daemon.DiskEncrypt.Decrypt" };
static constexpr char kActionChgPwd[] { "com.deepin.filemanager.daemon.DiskEncrypt.ChangePassphrase" };
static constexpr char kObjPath[] { "/com/deepin/filemanager/daemon/DiskEncrypt" };

ReencryptWorkerV2 *gFstabEncWorker { nullptr };

DiskEncryptDBus::DiskEncryptDBus(QObject *parent)
    : QObject(parent),
      QDBusContext()
{
    QDBusConnection::systemBus().registerObject(kObjPath, this);
    new DiskEncryptDBusAdaptor(this);

    dfmmount::DDeviceManager::instance();

    connect(SignalEmitter::instance(), &SignalEmitter::updateEncryptProgress,
            this, [this](const QString &dev, double progress) {
                Q_EMIT this->EncryptProgress(dev, deviceName, progress);
            },
            Qt::QueuedConnection);
    connect(SignalEmitter::instance(), &SignalEmitter::updateDecryptProgress,
            this, [this](const QString &dev, double progress) {
                Q_EMIT this->DecryptProgress(dev, deviceName, progress);
            },
            Qt::QueuedConnection);

    QtConcurrent::run([this] { diskCheck(); });
    triggerReencrypt();
}

DiskEncryptDBus::~DiskEncryptDBus()
{
}

QString DiskEncryptDBus::PrepareEncryptDisk(const QVariantMap &params)
{
    deviceName = params.value(encrypt_param_keys::kKeyDeviceName).toString();
    if (!checkAuth(kActionEncrypt)) {
        Q_EMIT PrepareEncryptDiskResult(params.value(encrypt_param_keys::kKeyDevice).toString(),
                                        deviceName,
                                        "",
                                        -kUserCancelled);
        return "";
    }

    auto jobID = JOB_ID.arg(QDateTime::currentMSecsSinceEpoch());
    PrencryptWorker *worker = new PrencryptWorker(jobID,
                                                  params,
                                                  this);
    connect(worker, &QThread::finished, this, [=] {
        running = false;
        int ret = worker->exitError();
        QString device = params.value(encrypt_param_keys::kKeyDevice).toString();

        qDebug() << "pre encrypt finished"
                 << device
                 << ret;

        if (params.value(encrypt_param_keys::kKeyInitParamsOnly).toBool()
            || ret != kSuccess) {
            Q_EMIT this->PrepareEncryptDiskResult(device,
                                                  deviceName,
                                                  jobID,
                                                  static_cast<int>(ret));
        } else {
            qInfo() << "start reencrypt device" << device;
            triggerReencrypt(device);
        }

        worker->deleteLater();
    });

    worker->start();
    running = true;

    return jobID;
}

QString DiskEncryptDBus::DecryptDisk(const QVariantMap &params)
{
    deviceName = params.value(encrypt_param_keys::kKeyDeviceName).toString();
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    if (!checkAuth(kActionDecrypt)) {
        Q_EMIT DecryptDiskResult(dev, deviceName, "", -kUserCancelled);
        return "";
    }

    auto jobID = JOB_ID.arg(QDateTime::currentMSecsSinceEpoch());

    QString pass = params.value(encrypt_param_keys::kKeyPassphrase).toString();
    if (dev.isEmpty()
        || (pass.isEmpty() && !params.value(encrypt_param_keys::kKeyInitParamsOnly).toBool())) {
        qDebug() << "cannot decrypt, params are not valid";
        return "";
    }

    DecryptWorker *worker = new DecryptWorker(jobID, params, this);
    connect(worker, &QThread::finished, this, [=] {
        running = false;
        int ret = worker->exitError();
        qDebug() << "decrypt device finished:"
                 << dev
                 << ret;
        Q_EMIT DecryptDiskResult(dev, deviceName, jobID, ret);
        worker->deleteLater();
    });
    worker->start();
    running = true;
    return jobID;
}

QString DiskEncryptDBus::ChangeEncryptPassphress(const QVariantMap &params)
{
    deviceName = params.value(encrypt_param_keys::kKeyDeviceName).toString();
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    if (!checkAuth(kActionChgPwd)) {
        Q_EMIT ChangePassphressResult(dev,
                                      deviceName,
                                      "",
                                      -kUserCancelled);
        return "";
    }

    auto jobID = JOB_ID.arg(QDateTime::currentMSecsSinceEpoch());
    ChgPassWorker *worker = new ChgPassWorker(jobID, params, this);
    connect(worker, &QThread::finished, this, [=] {
        running = false;
        int ret = worker->exitError();
        QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
        qDebug() << "change password finished:"
                 << dev
                 << ret;
        Q_EMIT ChangePassphressResult(dev, deviceName, jobID, ret);
        worker->deleteLater();
    });
    worker->start();
    running = true;
    return jobID;
}

void DiskEncryptDBus::IgnoreParamRequest()
{
    if (gFstabEncWorker)
        gFstabEncWorker->ignoreParamRequest();
}

void DiskEncryptDBus::ResumeEncryption(const QString &device)
{
    triggerReencrypt(device);
}

QString DiskEncryptDBus::QueryTPMToken(const QString &device)
{
    QString token;
    disk_encrypt_funcs::bcGetToken(device, &token);
    return token;
}

int DiskEncryptDBus::EncryptStatus(const QString &device)
{
    EncryptStates states;
    block_device_utils::bcDevEncryptStatus(device, &states);
    return states;
}

void DiskEncryptDBus::SetEncryptParams(const QVariantMap &params)
{
    if (!checkAuth(kActionEncrypt)) {
        Q_EMIT EncryptDiskResult(params.value(encrypt_param_keys::kKeyDevice).toString(),
                                 deviceName,
                                 -kUserCancelled,
                                 "");
        IgnoreParamRequest();
        return;
    }

    if (!gFstabEncWorker)
        return;

    gFstabEncWorker->setEncryptParams(params);
}

bool DiskEncryptDBus::HasPendingTask()
{
    QDir d("/boot/usec-crypt/");
    auto files = d.entryInfoList(QDir::Filter::NoDotAndDotDot | QDir::Filter::Files);
    for (const auto &file : files) {
        auto name = file.fileName();
        // search for decrypt.json, encrypt.json, encrypt_<dev>.json
        if (name.contains(QRegularExpression(R"((decrypt|encrypt|encrypt_.{3,})\.json)")))
            return true;
    }
    return false;
}

bool DiskEncryptDBus::IsWorkerRunning()
{
    return running;
}

void DiskEncryptDBus::onFstabDiskEncProgressUpdated(const QString &dev, qint64 offset, qint64 total)
{
    Q_EMIT EncryptProgress(currentEncryptingDevice, deviceName, (1.0 * offset) / total);
}

void DiskEncryptDBus::onFstabDiskEncFinished(const QString &dev, int result, const QString &errstr)
{
    qInfo() << "device has been encrypted: " << dev << result << errstr;
    Q_EMIT EncryptDiskResult(dev, deviceName, result != 0 ? -1000 : 0, "");
    if (result == 0) {
        qInfo() << "encrypt finished, remove encrypt config";
        ::remove(kEncConfigPath);
    }
}

bool DiskEncryptDBus::checkAuth(const QString &actID)
{
    return dpfSlotChannel->push("daemonplugin_core", "slot_Polkit_CheckAuth",
                                actID, message().service())
            .toBool();
}

bool DiskEncryptDBus::triggerReencrypt(const QString &device)
{
    gFstabEncWorker = new ReencryptWorkerV2(this);
    gFstabEncWorker->loadReencryptConfig(device);
    connect(gFstabEncWorker, &ReencryptWorkerV2::requestEncryptParams,
            this, &DiskEncryptDBus::RequestEncryptParams);
    connect(gFstabEncWorker, &ReencryptWorkerV2::deviceReencryptResult,
            this, [this](const QString &dev, int code, const QString &msg) {
                Q_EMIT EncryptDiskResult(dev, deviceName, code, msg);
            });
    connect(gFstabEncWorker, &ReencryptWorkerV2::finished,
            this, [this] {
                running = false;
                auto exitCode = gFstabEncWorker->exitError();
                gFstabEncWorker->deleteLater();
                gFstabEncWorker = nullptr;
                if (exitCode == -kIgnoreRequest)
                    return;
                // pick a new job.
                const static QRegularExpression reg(R"(encrypt_(.*).json)");
                QDir usecDir("/boot/usec-crypt");
                auto files = usecDir.entryInfoList();
                for (const auto &file : files) {
                    auto fileName = file.fileName();
                    if (fileName.contains(reg)) {
                        qInfo() << "found new unfinished job:" << fileName;
                        auto match = reg.match(fileName);
                        if (match.hasMatch()) {
                            auto dev = match.captured(1);
                            dev = "/dev/" + dev;
                            triggerReencrypt(dev);
                            return;
                        }
                    }
                }
            });

    currentEncryptingDevice = gFstabEncWorker->encryptConfig().devicePath;
    deviceName = gFstabEncWorker->encryptConfig().deviceName;
    qInfo() << "about to start encrypting" << currentEncryptingDevice;
    gFstabEncWorker->start();
    running = true;
    return true;
}

// this function should be running in thread.
// it may take times.
void DiskEncryptDBus::diskCheck()
{
    updateCrypttab();
}

void DiskEncryptDBus::getDeviceMapper(QMap<QString, QString> *dev2uuid, QMap<QString, QString> *uuid2dev)
{
    Q_ASSERT(dev2uuid && uuid2dev);
    using namespace dfmmount;
    auto monitor = DDeviceManager::instance()->getRegisteredMonitor(DeviceType::kBlockDevice).objectCast<DBlockMonitor>();
    Q_ASSERT(monitor);

    const QStringList &objPaths = monitor->getDevices();
    for (const auto &objPath : objPaths) {
        auto blkPtr = monitor->createDeviceById(objPath).objectCast<DBlockDevice>();
        if (!blkPtr) continue;

        QString uuid = blkPtr->getProperty(dfmmount::Property::kBlockIDUUID).toString();
        if (uuid.isEmpty()) continue;

        QString dev = blkPtr->device();
        uuid = QString("UUID=") + uuid;
        dev2uuid->insert(dev, uuid);
        uuid2dev->insert(uuid, dev);
    }
}

bool DiskEncryptDBus::updateCrypttab()
{
    qInfo() << "==== start checking crypttab...";
    QFile crypttab("/etc/crypttab");
    if (!crypttab.open(QIODevice::ReadWrite)) {
        qWarning() << "cannot open crypttab for rw";
        return false;
    }
    auto content = crypttab.readAll();
    crypttab.close();

    bool cryptUpdated = false;
    QByteArrayList lines = content.split('\n');
    for (int i = lines.count() - 1; i >= 0; --i) {
        QString line = lines.at(i);
        if (line.startsWith("#")) {
            qInfo() << "==== [ignore] comment:" << line;
            continue;
        }

        auto items = line.split(QRegularExpression(R"( |\t)"), QString::SkipEmptyParts);
        if (items.count() < 2) {
            lines.removeAt(i);
            qInfo() << "==== [remove] invalid line:" << line;
            continue;
        }

        if (isEncrypted(items.at(0), items.at(1)) == 0) {
            lines.removeAt(i);
            cryptUpdated = true;
            qInfo() << "==== [remove] this item is not encrypted:" << line;
            continue;
        }

        qInfo() << "==== [ keep ] device is still encrypted:" << line;
    }

    qInfo() << "==== end checking crypttab, crypttab is updated:" << cryptUpdated;
    if (cryptUpdated) {
        content = lines.join('\n');
        content.append("\n");
        if (!crypttab.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qWarning() << "cannot open cryppttab for update";
            return false;
        }
        crypttab.write(content);
        crypttab.close();
    }
    return cryptUpdated;
}

int DiskEncryptDBus::isEncrypted(const QString &target, const QString &source)
{
    QMap<QString, QString> dev2uuid, uuid2dev;
    getDeviceMapper(&dev2uuid, &uuid2dev);

    QString dev = source;
    if (dev.startsWith("UUID")) {
        dev = uuid2dev.value(dev);
        if (dev.isEmpty()) {
            qWarning() << "cannot find device by UUID, device might already decrypted." << source;
            return 0;
        }
    }

    if (dev.isEmpty()) {
        qWarning() << "cannot find device:" << target << source;
        return -1;
    }

    auto devPtr = block_device_utils::bcCreateBlkDev(dev);
    if (!devPtr) {
        qDebug() << "cannot construct device pointer by " << dev;
        return -2;
    }

    return devPtr->isEncrypted() ? 1 : 0;
}
