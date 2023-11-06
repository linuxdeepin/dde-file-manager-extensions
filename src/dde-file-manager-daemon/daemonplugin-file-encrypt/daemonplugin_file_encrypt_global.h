// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DAEMONPLUGIN_FILE_ENCRYPT_GLOBAL_H
#define DAEMONPLUGIN_FILE_ENCRYPT_GLOBAL_H

#include <QtCore/qglobal.h>
#include <QString>
#include <QDebug>

#if defined(DAEMONPLUGIN_FILE_ENCRYPT_LIBRARY)
#    define DAEMONPLUGIN_FILE_ENCRYPT_EXPORT Q_DECL_EXPORT
#else
#    define DAEMONPLUGIN_FILE_ENCRYPT_EXPORT Q_DECL_IMPORT
#endif

#define FILE_ENCRYPT_NS daemonplugin_file_encrypt
#define FILE_ENCRYPT_BEGIN_NS namespace FILE_ENCRYPT_NS {
#define FILE_ENCRYPT_END_NS }
#define FILE_ENCRYPT_USE_NS using namespace FILE_ENCRYPT_NS;

FILE_ENCRYPT_BEGIN_NS

namespace encrypt_param_keys {
inline constexpr char kKeyDevice[] { "device" };
inline constexpr char kKeyUUID[] { "uuid" };
inline constexpr char kKeyEncMode[] { "mode" };
inline constexpr char kKeyPassphrase[] { "passphrase" };
inline constexpr char kKeyCipher[] { "cipher" };
inline constexpr char kKeyRecoveryExportPath[] { "recoveryPath" };
inline constexpr char kKeyInitParamsOnly[] { "initParamsOnly" };
}   // namespace encrypt_param_keys

struct EncryptParams
{
    QString device;
    QString passphrase;
    QString cipher;
    QString recoveryPath;

    bool isValid() const
    {
        return !(device.isEmpty()
                 && passphrase.isEmpty()
                 && cipher.isEmpty());
    }
};

FILE_ENCRYPT_END_NS
#endif   // DAEMONPLUGIN_FILE_ENCRYPT_GLOBAL_H
