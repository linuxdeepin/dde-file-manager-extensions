// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef ENCRYPTWORKER_H
#define ENCRYPTWORKER_H

#include "daemonplugin_file_encrypt_global.h"

#include <QThread>
#include <QMutex>

FILE_ENCRYPT_BEGIN_NS
#define TOKEN_FILE_PATH QString("/tmp/%1_tpm_token.json")

class Worker : public QThread
{
    Q_OBJECT
public:
    explicit Worker(const QString &jobID, QObject *parent = nullptr)
        : QThread(parent), jobID(jobID) {}

    inline int exitError()
    {
        QMutexLocker locker(&mtx);
        return exitCode;
    }

protected:
    inline void setExitCode(int code)
    {
        QMutexLocker locker(&mtx);
        exitCode = code;
    }

protected:
    int exitCode { disk_encrypt::kSuccess };
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
    int cipherPos() const { return keyslotCipher; }
    int recKeyPos() const { return keyslotRecKey; }

protected:
    void run() override;
    int writeEncryptParams();
    int setFstabTimeout();

private:
    QVariantMap params;
    int keyslotCipher { -1 };
    int keyslotRecKey { -1 };
};

class ReencryptWorker : public Worker
{
    Q_OBJECT
public:
    explicit ReencryptWorker(const QString &dev,
                             const QString &passphrase,
                             QObject *parent = nullptr);

Q_SIGNALS:
    void updateReencryptProgress(const QString &device,
                                 double progress);
    void deviceReencryptResult(const QString &device,
                               int result);

protected:
    void run() override;

private:
    QString passphrase;
    QString device;
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
    int writeDecryptParams();

private:
    QVariantMap params;
};

class ChgPassWorker : public Worker
{
    Q_OBJECT
public:
    explicit ChgPassWorker(const QString &jobID,
                           const QVariantMap &params,
                           QObject *parent = nullptr);

protected:
    void run() override;

private:
    QVariantMap params;
};

FILE_ENCRYPT_END_NS

#endif   // ENCRYPTWORKER_H
