// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef ENCRYPTWORKER_H
#define ENCRYPTWORKER_H

#include "daemonplugin_file_encrypt_global.h"

#include <QThread>
#include <QMutex>

FILE_ENCRYPT_BEGIN_NS

class PrencryptWorker : public QThread
{
    Q_OBJECT
public:
    explicit PrencryptWorker(const QString &jobID,
                             const QVariantMap &params,
                             QObject *parent);

    inline int exitStatus()
    {
        QMutexLocker locker(&mtx);
        return exitCode;
    }

protected:
    void run() override;

private:
    QString jobID;
    QVariantMap params;
    QMutex mtx;
    int exitCode { 0 };
};

class ReencryptWorker : public QThread
{
    Q_OBJECT
public:
    explicit ReencryptWorker(QObject *parent = nullptr);

    inline int exitStatus()
    {
        QMutexLocker locker(&mtx);
        return exitCode;
    }

Q_SIGNALS:
    void updateReencryptProgress(const QString &device,
                                 double progress);
    void deviceReencryptResult(const QString &device,
                               int result);

protected:
    void run() override;

private:
    QMutex mtx;
    int exitCode { 0 };
};

class DecryptWorker : public QThread
{
    Q_OBJECT
public:
    explicit DecryptWorker(const QString &jobID,
                           const QString &device,
                           const QString &passphrase,
                           QObject *parent = nullptr);

protected:
    void run() override;

private:
    QString jobID;
    QString device;
    QString passphrase;
};

FILE_ENCRYPT_END_NS

#endif   // ENCRYPTWORKER_H
