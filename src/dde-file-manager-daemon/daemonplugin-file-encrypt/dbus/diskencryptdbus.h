// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DISKENCRYPTDBUS_H
#define DISKENCRYPTDBUS_H

#include "daemonplugin_file_encrypt_global.h"

#include <QObject>
#include <QDBusContext>

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
    QString ModifyEncryptPassphress(const QVariantMap &params);

Q_SIGNALS:
    void EncryptDiskPrepareResult(const QString &device, const QString &jobID, int errCode);
    void EncryptDiskResult(const QString &device, int errCode);
    void DecryptDiskResult(const QString &device, const QString &jobID, int errCode);
    void ModifyEncryptPassphressResult(const QString &device, const QString &jobID, int errCode);
    void EncryptProgress(const QString &device, double progress);
    void DecryptProgress(const QString &device, double progress);
};

FILE_ENCRYPT_END_NS
#endif   // DISKENCRYPTDBUS_H
