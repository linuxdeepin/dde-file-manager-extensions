// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTUTILS_H
#define ENCRYPTUTILS_H

#include <QString>

namespace dfmplugin_diskenc {
namespace encrypt_utils {
bool hasTPM();
}   // namespace encrypt_utils

namespace config_utils {
bool exportKeyEnabled();
QString cipherType();
}   // namespace config_utils

namespace fstab_utils {
bool isFstabItem(const QString &mpt);
}

}   // namespace dfmplugin_diskenc

#endif   // ENCRYPTUTILS_H
