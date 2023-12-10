// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DISKENCRYPTDBUS_H
#define DISKENCRYPTDBUS_H

#include "daemonplugin_file_encrypt_global.h"

#include <QObject>
#include <QDBusContext>
#include <QDBusServiceWatcher>

FILE_ENCRYPT_BEGIN_NS
class DiskEncryptDBus : public QObject, public QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "com.deepin.filemanager.daemon.DiskEncrypt")

public:
    explicit DiskEncryptDBus(QObject *parent = nullptr);
    ~DiskEncryptDBus();

public Q_SLOTS:
    QString PrepareEncryptDisk(const QVariantMap &params);
    QString DecryptDisk(const QVariantMap &params);
    QString ChangeEncryptPassphress(const QVariantMap &params);
    QString QueryTPMToken(const QString &device);

Q_SIGNALS:
    void PrepareEncryptDiskResult(const QString &device, const QString &jobID, int errCode);
    void EncryptDiskResult(const QString &device, int errCode);
    void DecryptDiskResult(const QString &device, const QString &jobID, int errCode);
    void ChangePassphressResult(const QString &device, const QString &jobID, int errCode);
    void EncryptProgress(const QString &device, double progress);
    void DecryptProgress(const QString &device, double progress);

private Q_SLOTS:
    void onEncryptDBusRegistered(const QString &service);
    void onEncryptDBusUnregistered(const QString &service);
    void onFstabDiskEncProgressUpdated(const QString &dev, qint64 offset, qint64 total);
    void onFstabDiskEncFinished(const QString &dev, int result, const QString &errstr);

private:
    bool checkAuth(const QString &actID);
    void startReencrypt(const QString &dev, const QString &passphrase, const QString &token);
    void setToken(const QString &dev, const QString &token);
    void triggerReencrypt();
    void diskCheck();
    static void getDeviceMapper(QMap<QString, QString> *dev2uuid, QMap<QString, QString> *uuid2dev);
    static bool updateCrypttab();
    static bool isEncrypted(const QString &device);
    static void updateInitrd();

    bool readEncryptDevice(QString *backingDev, QString *clearDev);

private:
    QSharedPointer<QDBusServiceWatcher> watcher;
    QString currentEncryptingDevice;
};

FILE_ENCRYPT_END_NS
#endif   // DISKENCRYPTDBUS_H
