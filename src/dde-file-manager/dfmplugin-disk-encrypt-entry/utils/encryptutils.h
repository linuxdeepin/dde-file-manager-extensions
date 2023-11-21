// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTUTILS_H
#define ENCRYPTUTILS_H

#include <QString>
#include <QVariantMap>

namespace dfmmount {
class DBlockDevice;
}

typedef QSharedPointer<dfmmount::DBlockDevice> BlockDev;

namespace dfmplugin_diskenc {

namespace tpm_utils {
bool hasTPM();
bool getRandomByTPM(int size, QString *output);
bool isSupportAlgoByTPM(const QString &algoName, bool *support);
bool encryptByTPM(const QVariantMap &map);
bool decryptByTPM(const QVariantMap &map, QString *psw);
}   // namespace tpm_utils

namespace tpm_passphrase_utils {
bool getAlgorithm(QString &hash, QString &key);
QString genPassphraseFromTPM(const QString &dev, const QString &pin);
QString getPassphraseFromTPM(const QString &dev, const QString &pin);
}

namespace config_utils {
bool exportKeyEnabled();
QString cipherType();
}   // namespace config_utils

namespace recovery_key_utils {
QString formatRecoveryKey(const QString &raw);
}

namespace fstab_utils {
bool isFstabItem(const QString &mpt);
}   // namespace fstab_utils

namespace device_utils {
int encKeyType(const QString &dev);
BlockDev createBlockDevice(const QString &devObjPath);
}   // namespace device_utils

namespace dialog_utils {
enum DialogType {
    kInfo,
    kWarning,
    kError,
};
void showDialog(const QString &title, const QString &msg, DialogType type);
}

}   // namespace dfmplugin_diskenc

#endif   // ENCRYPTUTILS_H
