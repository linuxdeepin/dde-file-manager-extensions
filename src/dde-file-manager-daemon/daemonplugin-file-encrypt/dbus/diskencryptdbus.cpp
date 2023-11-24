// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "diskencryptdbus.h"
#include "diskencryptdbus_adaptor.h"
#include "encrypt/encryptworker.h"
#include "notification/notifications.h"

#include <dfm-framework/dpf.h>
#include <dfm-mount/ddevicemanager.h>

#include <QDBusConnection>
#include <QtConcurrent>
#include <QDateTime>
#include <QDebug>

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
                           params.value(encrypt_param_keys::kKeyPassphrase).toString());
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
    if (dev.isEmpty() || pass.isEmpty()) {
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
    bool connected = conn("DiskReencryptProgress", SLOT(onFstabDiskEncProgressUpdated(const QString &, long, long)));
    connected &= conn("DiskReencryptResult", SLOT(onFstabDiskEncFinished(const QString &, int, const QString &);));
    qInfo() << service << "  signal connected: " << connected;
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
    bool disconnected = disconn("DiskReencryptProgress", SLOT(onFstabDiskEncProgressUpdated(const QString &, long, long)));
    disconnected &= disconn("DiskReencryptResult", SLOT(onFstabDiskEncFinished(const QString &, int, const QString &);));
    qInfo() << service << "  signal disconnected: " << disconnected;
}

void DiskEncryptDBus::onFstabDiskEncProgressUpdated(const QString &dev, long offset, long total)
{
    Q_EMIT EncryptProgress(dev, (1.0 * offset) / total);
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

void DiskEncryptDBus::startReencrypt(const QString &dev, const QString &passphrase)
{
    ReencryptWorker *worker = new ReencryptWorker(dev, passphrase, this);
    connect(worker, &ReencryptWorker::deviceReencryptResult,
            this, &DiskEncryptDBus::EncryptDiskResult);
    connect(worker, &QThread::finished, this, [=] {
        EncryptJobError ret = worker->exitError();
        qDebug() << "reencrypt finished"
                 << static_cast<int>(ret);
        worker->deleteLater();
    });
    worker->start();
}

void DiskEncryptDBus::triggerReencrypt()
{
    QString backingDev, clearDev;
    if (!readEncryptDevice(&backingDev, &clearDev)) {
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
    devHandler.close();
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
    QJsonValue devVal = config.value("device");
    QJsonValue volVal = config.value("volume");
    if (devVal.isUndefined() || volVal.isUndefined()) {
        qWarning() << "invalid encrypt config! device or volume is empty!";
        return false;
    }

    *backingDev = devVal.toString();
    *clearDev = volVal.toString();
    return true;
}
