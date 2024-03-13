// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DISK_ENCRYPT_H
#define DISK_ENCRYPT_H

#include "daemonplugin_file_encrypt_global.h"

#include <QVariantMap>
#include <QDBusUnixFileDescriptor>
#include <QDBusReply>

namespace dfmmount {
class DBlockDevice;
}   // namespace dfmmount

FILE_ENCRYPT_BEGIN_NS

enum EncryptVersion {
    kNotEncrypted,
    kVersionLUKS1,
    kVersionLUKS2,
    kVersionLUKSUnknown,

    kVersionUnknown = 10000,
};   // enum EncryptVersion

namespace disk_encrypt_funcs {
int bcInitHeaderFile(const EncryptParams &params, QString &headerPath, int *keyslotCipher, int *keyslotRecKey);
int bcGetToken(const QString &device, QString *tokenJson);
int bcInitHeaderDevice(const QString &device, const QString &passphrase, const QString &headerPath);
int bcSetToken(const QString &device, const QString &token);
int bcResumeReencrypt(const QString &device, const QString &passphrase, const QString &clearDev, bool expandFs = true);
int bcChangePassphrase(const QString &device, const QString &oldPassphrase, const QString &newPassphrase, int *keyslot);
int bcChangePassphraseByRecKey(const QString &device, const QString &oldPassphrase, const QString &newPassphrase, int *keyslot);
int bcDecryptDevice(const QString &device, const QString &passphrase);
int bcBackupCryptHeader(const QString &device, QString &headerPath);
int bcDoSetupHeader(const EncryptParams &params, QString *headerPath, int *keyslotCipher, int *keyslotRecKey);
int bcPrepareHeaderFile(const QString &device, QString *headerPath);
int bcSetLabel(const QString &device, const QString &label);
int bcOpenDevice(const QString &device, const QString &activeName);

int bcEncryptProgress(uint64_t size, uint64_t offset, void *usrptr);
int bcDecryptProgress(uint64_t size, uint64_t offset, void *usrptr);

}   // namespace disk_encrypt_funcs

namespace disk_encrypt_utils {
EncryptParams bcConvertParams(const QVariantMap &params);
bool bcValidateParams(const EncryptParams &params);
bool bcReadEncryptConfig(disk_encrypt::EncryptConfig *config, const QString &device = QString());

QString bcGenRecKey();
bool bcSaveRecoveryKey(const QString &dev, const QString &key, const QString &path);
}   // namespace disk_encrypt_utils

typedef QSharedPointer<dfmmount::DBlockDevice> DevPtr;
namespace block_device_utils {
DevPtr bcCreateBlkDev(const QString &device);
EncryptVersion bcDevEncryptVersion(const QString &device);
int bcDevEncryptStatus(const QString &device, disk_encrypt::EncryptStates *status);
bool bcIsMounted(const QString &device);
}   // namespace block_device_utils

namespace utils {
QDBusReply<QDBusUnixFileDescriptor> inhibit();
}

FILE_ENCRYPT_END_NS

#endif   // DISK_ENCRYPT_H
