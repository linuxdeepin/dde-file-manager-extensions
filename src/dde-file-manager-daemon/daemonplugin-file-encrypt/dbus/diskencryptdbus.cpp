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

    ReencryptWorker *worker = new ReencryptWorker(this);
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

DiskEncryptDBus::~DiskEncryptDBus()
{
}

QString DiskEncryptDBus::PrepareEncryptDisk(const QVariantMap &params)
{
    if (!checkAuth(kActionEncrypt)) {
        Q_EMIT EncryptDiskPrepareResult(params.value(encrypt_param_keys::kKeyDevice).toString(),
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
        Q_EMIT this->EncryptDiskPrepareResult(device,
                                              jobID,
                                              static_cast<int>(ret));
        qDebug() << "pre encrypt finished"
                 << device
                 << static_cast<int>(ret);
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

QString DiskEncryptDBus::ModifyEncryptPassphress(const QVariantMap &params)
{
    QString dev = params.value(encrypt_param_keys::kKeyDevice).toString();
    if (!checkAuth(kActionChgPwd)) {
        Q_EMIT ModifyEncryptPassphressResult(dev,
                                             "",
                                             static_cast<int>(EncryptJobError::kUserCancelled));
        return "";
    }

    auto jobID = JOB_ID.arg(QDateTime::currentMSecsSinceEpoch());
    qDebug() << "yeah! you invoked me" << __FUNCTION__;
    qDebug() << "with params: " << params;
    return jobID;
}

bool DiskEncryptDBus::checkAuth(const QString &actID)
{
    return dpfSlotChannel->push("daemonplugin_core", "slot_Polkit_CheckAuth",
                                actID, message().service())
            .toBool();
}
