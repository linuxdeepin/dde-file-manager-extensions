// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DISK_ENCRYPT_H
#define DISK_ENCRYPT_H

#include "daemonplugin_file_encrypt_global.h"

#include <QVariantMap>

namespace dfmmount {
class DBlockDevice;
}   // namespace dfmmount

FILE_ENCRYPT_BEGIN_NS

enum EncryptStatus {
    kNotEncrypted,
    kLUKS1,
    kLUKS2,
    kUnknownLUKS,

    kStatusError = 10000,
};   // enum EncryptStatus

enum EncryptError {
    kNoError,
    kParamsNotValid,
    kDeviceMounted,
    kDeviceEncrypted,

    kUnknownError,
};   // enum EncryptError

namespace disk_encrypt_funcs {
EncryptError bcInitHeaderFile(const EncryptParams &params, QString &headerPath);
QString bcDoSetupHeader(const EncryptParams &params);
int bcInitHeaderDevice(const QString &device, const QString &passphrase, const QString &headerPath);
int bcResumeReencrypt(const QString &device, const QString &passphrase);
int bcChangePassphrase(const QString &device, const QString &oldPassphrase, const QString &newPassphrase);
int bcDecryptDevice(const QString &device, const QString &passphrase);
int bcBackupCryptHeader(const QString &device, QString &headerPath);
QString bcPrepareHeaderFile(const QString &device);

int bcEncryptProgress(uint64_t size, uint64_t offset, void *usrptr);
int bcDecryptProgress(uint64_t size, uint64_t offset, void *usrptr);
}   // namespace disk_encrypt_funcs

namespace disk_encrypt_utils {
EncryptParams bcConvertParams(const QVariantMap &params);
bool bcValidateParams(const EncryptParams &params);

void bcPendTask(const QString &device, const QString &passphrase);
void bcClearPendingTasks();
QStringList bcPendingTasks();

QString bcExpRecFile(const EncryptParams &params);
QString bcGenRecKey();
}   // namespace disk_encrypt_utils

typedef QSharedPointer<dfmmount::DBlockDevice> DevPtr;
namespace block_device_utils {
DevPtr bcCreateBlkDev(const QString &device);
EncryptStatus bcDevStatus(const QString &device);
bool bcIsMounted(const QString &device);
}   // namespace block_device_utils

FILE_ENCRYPT_END_NS

#endif   // DISK_ENCRYPT_H
