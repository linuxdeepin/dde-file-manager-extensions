// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTUTILS_H
#define ENCRYPTUTILS_H

#include <QString>
#include <QVariantMap>

namespace dfmplugin_diskenc {

namespace tpm_utils {
bool hasTPM();
bool getRandomByTPM(int size, QString *output);
bool isSupportAlgoByTPM(const QString &algoName, bool *support);
bool encryptByTPM(const QVariantMap &map);
bool decryptByTPM(const QVariantMap &map, QString *psw);
}   // namespace tpm_utils

namespace config_utils {
bool exportKeyEnabled();
QString cipherType();
}   // namespace config_utils

namespace fstab_utils {
bool isFstabItem(const QString &mpt);
}

}   // namespace dfmplugin_diskenc

#endif   // ENCRYPTUTILS_H
