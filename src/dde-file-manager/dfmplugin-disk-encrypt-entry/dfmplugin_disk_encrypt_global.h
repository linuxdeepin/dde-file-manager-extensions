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

inline constexpr char kDaemonBusName[] { "com.deepin.filemanager.daemon" };
inline constexpr char kDaemonBusPath[] { "/com/deepin/filemanager/daemon/DiskEncrypt" };
inline constexpr char kDaemonBusIface[] { "com.deepin.filemanager.daemon.DiskEncrypt" };

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

inline constexpr int kPasswordSize { 8 };
inline const QString kTPMKeyPath(QDir::homePath() + "/.TPMKey");
inline constexpr char kTPMHashAlgo[] { "sha256" };
inline constexpr char kTPMKeyAlgo[] { "aes" };

#define DEV_ENCTYPE_CFG "/etc/deepin/dde-file-manager/dev_enc_type.ini"
#define DEV_KEY QString("device/%1")

#endif   // DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H
