// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef GLOBALTYPESDEFINE_H
#define GLOBALTYPESDEFINE_H

#include <QString>
#include <QStringList>

namespace disk_encrypt {

namespace encrypt_param_keys {
inline constexpr char kKeyDevice[] { "device" };
inline constexpr char kKeyUUID[] { "uuid" };
inline constexpr char kKeyEncMode[] { "mode" };
inline constexpr char kKeyPassphrase[] { "passphrase" };
inline constexpr char kKeyOldPassphrase[] { "oldPassphrase" };
inline constexpr char kKeyCipher[] { "cipher" };
inline constexpr char kKeyRecoveryExportPath[] { "exportRecKeyTo" };
inline constexpr char kKeyInitParamsOnly[] { "initParamsOnly" };
inline constexpr char kKeyMountPoint[] { "mountpoint" };
inline constexpr char kKeyTPMConfig[] { "tpmConfig" };
inline constexpr char kKeyTPMToken[] { "tpmToken" };
inline constexpr char kKeyValidateWithRecKey[] { "usingRecKey" };
inline constexpr char kKeyDeviceName[] { "deviceName" };
}   // namespace encrypt_param_keys

inline const QStringList kDisabledEncryptPath {
    "/",
    "/boot",
    "/boot/efi",
    "/recovery"
};

enum EncryptOperationStatus {
    kSuccess = 0,
    kUserCancelled,
    kRebootRequired,

    kErrorParamsInvalid,
    kErrorDeviceMounted,
    kErrorDeviceEncrypted,
    kErrorWrongPassphrase,
    kErrorEncryptBusy,
    kErrorCannotStartEncryptJob,
    kErrorCreateHeader,
    kErrorBackupHeader,
    kErrorApplyHeader,
    kErrorInitCrypt,
    kErrorInitReencrypt,
    kErrorRestoreFromFile,
    kErrorActive,
    kErrorDeactive,
    kErrorLoadCrypt,
    kErrorGetReencryptFlag,
    kErrorWrongFlags,
    kErrorSetOffset,
    kErrorFormatLuks,
    kErrorAddKeyslot,
    kErrorReencryptFailed,
    kErrorDecryptFailed,
    kErrorOpenFstabFailed,
    kErrorChangePassphraseFailed,
    kErrorOpenFileFailed,
    kErrorSetTokenFailed,
    kErrorResizeFs,
    kErrorDisabledMountPoint,

    kErrorUnknown,
};

enum SecKeyType {
    kPasswordOnly,
    kTPMAndPIN,
    kTPMOnly,
};

struct DeviceEncryptParam
{
    QString devDesc;
    QString uuid;
    SecKeyType type;
    QString key;
    QString newKey;
    QString exportPath;
    QString deviceDisplayName;
    QString mountPoint;
    bool initOnly;
    bool validateByRecKey;
};

}

#endif   // GLOBALTYPESDEFINE_H
