// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DISKENCRYPTENTRY_H
#define DISKENCRYPTENTRY_H

#include "dfmplugin_disk_encrypt_global.h"

#include <dfm-framework/dpf.h>

namespace dfmplugin_diskenc {

class EncryptProcessDialog;
class DFMPLUGIN_DISK_ENCRYPT_EXPORT DiskEncryptEntry : public dpf::Plugin
{
    Q_OBJECT

    Q_PLUGIN_METADATA(IID "org.deepin.plugin.filemanager" FILE "diskencryptentry.json")

    // Plugin interface
public:
    virtual void initialize() override;
    virtual bool start() override;

protected:
    void connectDaemonSignals();

protected Q_SLOTS:
    void onPreencryptResult(const QString &, const QString &, int);
    void onEncryptResult(const QString &, int);
    void onEncryptProgress(const QString &, double);
    void onDecryptResult(const QString &, const QString &, int);
    void onDecryptProgress(const QString &, double);

private:
    void onComputerMenuSceneAdded(const QString &scene);

private:
    QMap<QString, EncryptProcessDialog *> encryptDialogs;
    QMap<QString, EncryptProcessDialog *> decryptDialogs;
};
}

#endif   // DISKENCRYPTENTRY_H
