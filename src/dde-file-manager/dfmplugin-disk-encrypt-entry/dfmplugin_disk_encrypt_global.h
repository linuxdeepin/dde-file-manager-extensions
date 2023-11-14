// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H
#define DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H

#include <QtCore/qglobal.h>
#include <QDir>
#include <QString>

#if defined(DFMPLUGIN_DISK_ENCRYPT_LIBRARY)
#    define DFMPLUGIN_DISK_ENCRYPT_EXPORT Q_DECL_EXPORT
#else
#    define DFMPLUGIN_DISK_ENCRYPT_EXPORT Q_DECL_IMPORT
#endif

enum TPMModuleEncType {
    kUnknow = 0,
    kUseTpmAndPcr,
    kUseTpmAndPin
};

inline constexpr char kDaemonBusName[] { "com.deepin.filemanager.daemon" };
inline constexpr char kDaemonBusPath[] { "/com/deepin/filemanager/daemon/DiskEncrypt" };
inline constexpr char kDaemonBusIface[] { "com.deepin.filemanager.daemon.DiskEncrypt" };

inline constexpr char kMenuPluginName[] { "dfmplugin_menu" };
inline constexpr char kComputerMenuSceneName[] { "ComputerMenu" };

enum EncryptJobError {
    kNoError = 0,
    kHasPendingEncryptJob = -1,
    kCannotCreateEncryptJob = -2,
    kInvalidEncryptParams = -3,
    kCannotInitEncryptHeaderFile = -4,
    kCannotInitEncryptHeaderDevice = -5,
    kReencryptFailed = -6,
    kDecryptFailed = -7,
    kFstabOpenFailed = -8,
    kUserCancelled = -9,
    kChgPassphraseFailed = -10,
};

inline constexpr int kPasswordSize { 14 };
inline const QString kTPMKeyPath(QDir::homePath() + "/.TPMKey");
inline constexpr char kTPMHashAlgo[] { "sha256" };
inline constexpr char kTPMKeyAlgo[] { "aes" };
inline constexpr char kTCMHashAlgo[] { "sm3_256" };
inline constexpr char kTCMKeyAlgo[] { "sm4" };
inline constexpr char kConfigKeyPriHashAlgo[] { "primary_hash_algo" };
inline constexpr char kConfigKeyPriKeyAlgo[] { "primary_key_algo" };

#endif   // DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H
