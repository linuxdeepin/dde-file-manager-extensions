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
