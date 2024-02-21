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
    void SetEncryptParams(const QVariantMap &params);

Q_SIGNALS:
    void PrepareEncryptDiskResult(const QString &device, const QString &devName, const QString &jobID, int errCode);
    void EncryptDiskResult(const QString &device, const QString &devName, int errCode);
    void DecryptDiskResult(const QString &device, const QString &devName, const QString &jobID, int errCode);
    void ChangePassphressResult(const QString &device, const QString &devName, const QString &jobID, int errCode);
    void EncryptProgress(const QString &device, const QString &devName, double progress);
    void DecryptProgress(const QString &device, const QString &devName, double progress);
    void RequestEncryptParams(const QVariantMap &encConfig);

private Q_SLOTS:
    void onFstabDiskEncProgressUpdated(const QString &dev, qint64 offset, qint64 total);
    void onFstabDiskEncFinished(const QString &dev, int result, const QString &errstr);

private:
    bool checkAuth(const QString &actID);
    void diskCheck();
    bool triggerReencrypt(const QString &device = QString());
    static void getDeviceMapper(QMap<QString, QString> *dev2uuid, QMap<QString, QString> *uuid2dev);
    static bool updateCrypttab();
    static int isEncrypted(const QString &target, const QString &source);

private:
    QString currentEncryptingDevice;
    QString deviceName;
};

FILE_ENCRYPT_END_NS
#endif   // DISKENCRYPTDBUS_H
