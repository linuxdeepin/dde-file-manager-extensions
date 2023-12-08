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

#include <QDBusConnection>
#include <QtConcurrent>
#include <QDateTime>
#include <QDebug>
#include <QSettings>

#include <libcryptsetup.h>

FILE_ENCRYPT_USE_NS

#define JOB_ID QString("job_%1")
static constexpr char kActionEncrypt[] { "com.deepin.filemanager.daemon.DiskEncrypt.Encrypt" };
static constexpr char kActionDecrypt[] { "com.deepin.filemanager.daemon.DiskEncrypt.Decrypt" };
static constexpr char kActionChgPwd[] { "com.deepin.filemanager.daemon.DiskEncrypt.ChangePassphrase" };
static constexpr char kObjPath[] { "/com/deepin/filemanager/daemon/DiskEncrypt" };
static constexpr char kEncConfigPath[] { "/boot/usec-crypt/encrypt.json" };

DiskEncryptDBus::DiskEncryptDBus(QObject *parent)
    : QObject(parent),
      QDBusContext()
{
    QDBusConnection::systemBus().registerObject(kObjPath, this);
    new DiskEncryptDBusAdaptor(this);

    dfmmount::DDeviceManager::instance();

    connect(SignalEmitter::instance(), &SignalEmitter::updateEncryptProgress,
            this, &DiskEncryptDBus::EncryptProgress, Qt::QueuedConnection);
    connect(SignalEmitter::instance(), &SignalEmitter::updateDecryptProgress,
            this, &DiskEncryptDBus::DecryptProgress, Qt::QueuedConnection);

    watcher.reset(new QDBusServiceWatcher("org.deepin.UsecCrypt", QDBusConnection::systemBus()));
    connect(watcher.data(), &QDBusServiceWatcher::serviceRegistered,
            this, &DiskEncryptDBus::onEncryptDBusRegistered);
    connect(watcher.data(), &QDBusServiceWatcher::serviceUnregistered,
            this, &DiskEncryptDBus::onEncryptDBusUnregistered);

    triggerReencrypt();

    QtConcurrent::run([this]{ diskCheck(); });
}

DiskEncryptDBus::~DiskEncryptDBus()
{
}

QString DiskEncryptDBus::PrepareEncryptDisk(const QVariantMap &params)
{
    if (!checkAuth(kActionEncrypt)) {
        Q_EMIT PrepareEncryptDiskResult(params.value(encrypt_param_keys::kKeyDevice).toString(),
                                        "",
                                        static_cast<int>(EncryptJobError::kUserCancelled));
        return "";
    }

    auto jobID = JOB_ID.arg(QDateTime::currentMSecsSinceEpoch());
    PrencryptWorker *worker = new PrencryptWorker(jobID,
                                                  params,
                                                  this);
    connect(worker, &QThread::finished, this, [=] {
        EncryptJobError ret = worker->exitError();
        QString device = params.value(encrypt_param_keys::kKeyDevice).toString();

        qDebug() << "pre encrypt finished"
                 << device
                 << static_cast<int>(ret);

        if (params.value(encrypt_param_keys::kKeyInitParamsOnly).toBool()
            || ret != EncryptJobError::kNoError) {
            Q_EMIT this->PrepareEncryptDiskResult(device,
                                                  jobID,
                                                  static_cast<int>(ret));
        } else {
            qInfo() << "start reencrypt device" << device;
            startReencrypt(device,
                           params.value(encrypt_param_keys::kKeyPassphrase).toString(),
                           params.value(encrypt_param_keys::kKeyTPMToken).toString());
        }

        worker->deleteLater();
    });

    worker->start();

    return jobID;
}

QString DiskEncryptDBus::DecryptDisk(const QVariantMap &params)
{
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    if (!checkAuth(kActionDecrypt)) {
        Q_EMIT DecryptDiskResult(dev, "", static_cast<int>(EncryptJobError::kUserCancelled));
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
        EncryptJobError ret = worker->exitError();
        qDebug() << "decrypt device finished:"
                 << dev
                 << static_cast<int>(ret);
        Q_EMIT DecryptDiskResult(dev, jobID, static_cast<int>(ret));
        worker->deleteLater();
    });
    worker->start();
    return jobID;
}

QString DiskEncryptDBus::ChangeEncryptPassphress(const QVariantMap &params)
{
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    if (!checkAuth(kActionChgPwd)) {
        Q_EMIT ChangePassphressResult(dev,
                                      "",
                                      static_cast<int>(EncryptJobError::kUserCancelled));
        return "";
    }

    auto jobID = JOB_ID.arg(QDateTime::currentMSecsSinceEpoch());
    ChgPassWorker *worker = new ChgPassWorker(jobID, params, this);
    connect(worker, &QThread::finished, this, [=] {
        EncryptJobError ret = worker->exitError();
        QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
        qDebug() << "change password finished:"
                 << dev
                 << static_cast<int>(ret);
        Q_EMIT ChangePassphressResult(dev, jobID, static_cast<int>(ret));
        worker->deleteLater();
    });
    worker->start();
    return jobID;
}

QString DiskEncryptDBus::QueryTPMToken(const QString &device)
{
    QString token;
    disk_encrypt_funcs::bcGetToken(device, &token);
    return token;
}

void DiskEncryptDBus::onEncryptDBusRegistered(const QString &service)
{
    qInfo() << service << "registered";
    auto conn = [=](const char *sig, const char *slot) -> bool {
        return QDBusConnection::systemBus().connect("org.deepin.UsecCrypt",
                                                    "/org/deepin/UsecCrypt",
                                                    "org.deepin.UsecCrypt",
                                                    sig,
                                                    this,
                                                    slot);
    };
    bool connected = conn("DiskReencryptProgress", SLOT(onFstabDiskEncProgressUpdated(const QString &, qint64, qint64)));
    qInfo() << service << "  signal connected: " << connected << "DiskReencryptProgress";
    connected &= conn("DiskReencryptResult", SLOT(onFstabDiskEncFinished(const QString &, int, const QString &)));
    qInfo() << service << "  signal connected: " << connected << "DiskReencryptResult";
}

void DiskEncryptDBus::onEncryptDBusUnregistered(const QString &service)
{
    qInfo() << service << "unregistered";
    auto disconn = [=](const char *sig, const char *slot) -> bool {
        return QDBusConnection::systemBus().disconnect("org.deepin.UsecCrypt",
                                                       "/org/deepin/UsecCrypt",
                                                       "org.deepin.UsecCrypt",
                                                       sig,
                                                       this,
                                                       slot);
    };
    bool disconnected = disconn("DiskReencryptProgress", SLOT(onFstabDiskEncProgressUpdated(const QString &, qint64, qint64)));
    disconnected &= disconn("DiskReencryptResult", SLOT(onFstabDiskEncFinished(const QString &, int, const QString &)));
    qInfo() << service << "  signal disconnected: " << disconnected;
}

void DiskEncryptDBus::onFstabDiskEncProgressUpdated(const QString &dev, qint64 offset, qint64 total)
{
    Q_EMIT EncryptProgress(currentEncryptingDevice, (1.0 * offset) / total);
}

void DiskEncryptDBus::onFstabDiskEncFinished(const QString &dev, int result, const QString &errstr)
{
    qInfo() << "device has been encrypted: " << dev << result << errstr;
    Q_EMIT EncryptDiskResult(dev, result != 0 ? -1000 : 0);
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

void DiskEncryptDBus::startReencrypt(const QString &dev, const QString &passphrase, const QString &token)
{
    ReencryptWorker *worker = new ReencryptWorker(dev, passphrase, this);
    connect(worker, &ReencryptWorker::deviceReencryptResult,
            this, &DiskEncryptDBus::EncryptDiskResult);
    connect(worker, &QThread::finished, this, [=] {
        EncryptJobError ret = worker->exitError();
        qDebug() << "reencrypt finished"
                 << static_cast<int>(ret);
        worker->deleteLater();
        setToken(dev, token);
    });
    worker->start();
}

void DiskEncryptDBus::setToken(const QString &dev, const QString &token)
{
    if (token.isEmpty())
        return;

    int ret = disk_encrypt_funcs::bcSetToken(dev, token.toStdString().c_str());
    if (ret != 0)
        qWarning() << "set token failed for device" << dev;
}

void DiskEncryptDBus::triggerReencrypt()
{
    QString clearDev;
    if (!readEncryptDevice(&currentEncryptingDevice, &clearDev)) {
        qInfo() << "no encrypt config or config is invalid.";
        return;
    }

    QFile devHandler("/dev/usec_crypt");
    if (!devHandler.exists()) {
        qWarning() << "no device handler exists!";
        return;
    }

    if (!devHandler.open(QIODevice::WriteOnly)) {
        qWarning() << "device handler open failed!";
        return;
    }

    if (0 > devHandler.write(clearDev.toLocal8Bit())) {
        qWarning() << "reencrypt trigger failed!";
        devHandler.close();
        return;
    }

    qInfo() << "about to start encrypting" << clearDev;
    QTimer::singleShot(1000, qApp, []{
        QtConcurrent::run([]{ updateInitrd(); });
    });
    devHandler.close();
}

void DiskEncryptDBus::diskCheck()
{
    QMap<QString, QString> dev2uuid, uuid2dev;
    getDeviceMapper(&dev2uuid, &uuid2dev);

    // QStringList decrypted;
    // if (decrypted.isEmpty())
    //     return;

    // qDebug() << "these devices are not encrypted anymore:" << decrypted;

    // updateCrypttab(decrypted);
    updateInitrd();
}

void DiskEncryptDBus::getDeviceMapper(QMap<QString, QString> *dev2uuid, QMap<QString, QString> *uuid2dev)
{
    Q_ASSERT(dev2uuid && uuid2dev);
    using namespace dfmmount;
    auto monitor = DDeviceManager::instance()->getRegisteredMonitor(DeviceType::kBlockDevice)
                       .objectCast<DBlockMonitor>();
    Q_ASSERT(monitor);

    const QStringList &objPaths = monitor->getDevices();
    for (const auto &objPath: objPaths) {
        auto blkPtr = monitor->createDeviceById(objPath).objectCast<DBlockDevice>();
        if (!blkPtr) continue;
        QString uuid = blkPtr->getProperty(dfmmount::Property::kBlockIDUUID).toString();
        if (uuid.isEmpty()) continue;
        bool isLuks = blkPtr->getProperty(dfmmount::Property::kBlockIDType).toString().startsWith("luks_");
        if (isLuks) continue;
        bool isClear = blkPtr->getProperty(dfmmount::Property::kEncryptedCleartextDevice).toString().length() > 1;
        if (isClear) continue;
        QString dev = blkPtr->device();
        uuid = QString("UUID=") + uuid;
        dev2uuid->insert(dev, uuid);
        uuid2dev->insert(uuid, dev);
    }
}

void DiskEncryptDBus::updateCrypttab(const QStringList &decryptedDevs)
{
    QFile crypttab("/etc/crypttab");
    if (!crypttab.open(QIODevice::ReadWrite)) {
        qWarning() << "cannot open crypttab for rw";
        return;
    }
    auto content = crypttab.readAll();
    crypttab.close();
    QByteArrayList lines = content.split('\n');
    for (int i = lines.count() - 1; i >= 0; --i) {
        QString line = lines.at(i);
        auto items = line.split(QRegularExpression(R"( |\t)"), QString::SkipEmptyParts);
        if (items.count() < 2) continue;
        if (decryptedDevs.contains(items.at(1)))
            lines.removeAt(i);
    }
    content = lines.join('\n');
    if (!crypttab.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open cryppttab for update";
        return;
    }
    crypttab.write(content);
    crypttab.close();
}

void DiskEncryptDBus::updateInitrd()
{
    int ret = system("update-initramfs -u");
    qDebug() << "initramfs updated: " << ret;
}

bool DiskEncryptDBus::readEncryptDevice(QString *backingDev, QString *clearDev)
{
    Q_ASSERT(backingDev && clearDev);

    QFile encConfig(kEncConfigPath);
    if (!encConfig.exists()) {
        qInfo() << "the encrypt config file doesn't exist";
        return false;
    }

    if (!encConfig.open(QIODevice::ReadOnly)) {
        qWarning() << "encrypt config file open failed!";
        return false;
    }

    QJsonDocument doc = QJsonDocument::fromJson(encConfig.readAll());
    encConfig.close();
    QJsonObject config = doc.object();
    QJsonValue devVal = config.value("device_path");
    QJsonValue volVal = config.value("volume");
    if (devVal.isUndefined() || volVal.isUndefined()) {
        qWarning() << "invalid encrypt config! device or volume is empty!";
        return false;
    }

    *backingDev = devVal.toString();
    *clearDev = volVal.toString();
    return true;
}
