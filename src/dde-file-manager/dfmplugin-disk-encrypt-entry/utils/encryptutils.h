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
int checkTPM();
int getRandomByTPM(int size, QString *output);
int isSupportAlgoByTPM(const QString &algoName, bool *support);
int encryptByTPM(const QVariantMap &map);
int decryptByTPM(const QVariantMap &map, QString *psw);
}   // namespace tpm_utils

namespace tpm_passphrase_utils {

enum TPMError {
    kTPMNoError,
    kTPMEncryptFailed,
    kTPMLocked,
    kTPMNoRandomNumber,
    kTPMMissingAlog,
};

bool getAlgorithm(QString *sessionHashAlgo, QString *sessionKeyAlgo,
                  QString *primaryHashAlgo, QString *primaryKeyAlgo,
                  QString *minorHashAlgo, QString *minorKeyAlgo);
int genPassphraseFromTPM(const QString &dev, const QString &pin, QString *passphrase);
QString getPassphraseFromTPM(const QString &dev, const QString &pin);
void cacheToken(const QString &device, const QVariantMap &token);

}   // namespace tpm_passphrase_utils

namespace config_utils {
bool exportKeyEnabled();
QString cipherType();
}   // namespace config_utils

namespace passphrase_utils {
QString formatRecoveryKey(const QString &raw);

QString pubKey();
int encryptPassphrase(const QString &input, QString *output);
}   // namespace passphrase_utils

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
void showTPMError(const QString &title, tpm_passphrase_utils::TPMError err);
}   // namespace dialog_utils

}   // namespace dfmplugin_diskenc

#endif   // ENCRYPTUTILS_H
