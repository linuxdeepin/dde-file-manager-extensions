// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef ENCRYPTWORKER_H
#define ENCRYPTWORKER_H

#include "daemonplugin_file_encrypt_global.h"

#include <QThread>
#include <QMutex>

FILE_ENCRYPT_BEGIN_NS

enum class EncryptJobError {
    kNoError = 0,
    kHasPendingEncryptJob = -1,
    kCannotCreateEncryptJob = -2,
    kInvalidEncryptParams = -3,
    kCannotInitEncryptHeaderFile = -4,
    kCannotInitEncryptHeaderDevice = -5,
    kReencryptFailed = -6,
    kDecryptFailed = -7,
    kFstabOpenFailed = -8,
};

class Worker : public QThread
{
    Q_OBJECT
public:
    explicit Worker(const QString &jobID, QObject *parent = nullptr)
        : QThread(parent), jobID(jobID) { }

    inline EncryptJobError exitError()
    {
        QMutexLocker locker(&mtx);
        return exitCode;
    }

protected:
    inline void setExitCode(EncryptJobError code)
    {
        QMutexLocker locker(&mtx);
        exitCode = code;
    }

protected:
    EncryptJobError exitCode { EncryptJobError::kNoError };
    QString jobID;
    QMutex mtx;
};

class PrencryptWorker : public Worker
{
    Q_OBJECT
public:
    explicit PrencryptWorker(const QString &jobID,
                             const QVariantMap &params,
                             QObject *parent);

protected:
    void run() override;
    EncryptJobError writeEncryptParams();
    EncryptJobError setFstabTimeout();

private:
    QVariantMap params;
};

class ReencryptWorker : public Worker
{
    Q_OBJECT
public:
    explicit ReencryptWorker(QObject *parent = nullptr);

Q_SIGNALS:
    void updateReencryptProgress(const QString &device,
                                 double progress);
    void deviceReencryptResult(const QString &device,
                               int result);

protected:
    void run() override;

private:
};

class DecryptWorker : public Worker
{
    Q_OBJECT
public:
    explicit DecryptWorker(const QString &jobID,
                           const QVariantMap &params,
                           QObject *parent = nullptr);

protected:
    void run() override;
    EncryptJobError writeDecryptParams();

private:
    QVariantMap params;
};

FILE_ENCRYPT_END_NS

#endif   // ENCRYPTWORKER_H
