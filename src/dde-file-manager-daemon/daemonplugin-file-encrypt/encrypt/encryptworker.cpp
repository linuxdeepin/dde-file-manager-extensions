// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "encryptworker.h"
#include "diskencrypt.h"

FILE_ENCRYPT_USE_NS

PrencryptWorker::PrencryptWorker(const QString &jobID,
                                 const QVariantMap &params,
                                 QObject *parent)
    : QThread(parent),
      jobID(jobID),
      params(params)
{
}

void PrencryptWorker::run()
{
    auto encParams = disk_encrypt_utils::bcConvertEncParams(params);
    if (!disk_encrypt_utils::bcValidateParams(encParams)) {
        QMutexLocker locker(&mtx);
        exitCode = -1;
        qDebug() << "invalid params" << params;
        return;
    }

    QString localHeaderFile;
    EncryptError err = disk_encrypt_funcs::bcInitHeaderFile(encParams,
                                                            localHeaderFile);
    if (err != kNoError || localHeaderFile.isEmpty()) {
        QMutexLocker locker(&mtx);
        exitCode = -2;
        qDebug() << "cannot generate local header"
                 << params;
        return;
    }

    int ret = disk_encrypt_funcs::bcInitHeaderDevice(encParams.device,
                                                     encParams.passphrase,
                                                     localHeaderFile);
    if (ret != 0) {
        QMutexLocker locker(&mtx);
        exitCode = -3;
        qDebug() << "cannot init device encrypt"
                 << params;
        return;
    }
    exitCode = 0;
}

ReencryptWorker::ReencryptWorker(QObject *parent)
    : QThread(parent)
{
}

void ReencryptWorker::run()
{
    auto resumeList = disk_encrypt_utils::bcResumeDeviceList();
    QStringList uncompleted;

    for (const auto &resumeItem : resumeList) {
        QStringList devInfo = resumeItem.split(" ", Qt::SkipEmptyParts);
        if (devInfo.count() != 2)
            return;
        int ret = disk_encrypt_funcs::bcResumeReencrypt(devInfo[0],
                                                        devInfo[1]);
        if (ret != 0)
            uncompleted.append(resumeItem);

        Q_EMIT deviceReencryptResult(devInfo[0], ret);
    }

    if (!uncompleted.isEmpty()) {
        qDebug() << "devices are not completly encrypted..."
                 << uncompleted;
        QMutexLocker locker(&mtx);
        exitCode = -1;
    }
    disk_encrypt_utils::bcClearCachedPendingList();
}

DecryptWorker::DecryptWorker(const QString &jobID,
                             const QString &device,
                             const QString &passphrase,
                             QObject *parent)
    : QThread(parent),
      jobID(jobID),
      device(device),
      passphrase(passphrase)

{
}
void DecryptWorker::run()
{
    int ret = disk_encrypt_funcs::bcDecryptDevice(device, passphrase);
    if (ret < 0) {
        qDebug() << "decrypt devcei failed"
                 << device
                 << ret;
    }
}
