// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "eventreceiver.h"
#include "tpm/tpmwork.h"

#include <dfm-framework/event/event.h>

Q_DECLARE_METATYPE(QString *)
Q_DECLARE_METATYPE(bool *)

DPENCRYPTMANAGER_USE_NAMESPACE

EventReceiver *EventReceiver::instance()
{
    static EventReceiver ins;
    return &ins;
}

bool EventReceiver::tpmIsAvailable()
{
    TPMWork tpm;
    return tpm.checkTPMAvailable();
}

bool EventReceiver::getRandomByTpm(int size, QString *output)
{
    TPMWork tpm;
    if (!tpm.getRandom(size, output))
        return false;


    // Determine whether the password is a hexadecimal character
    QString out = *output;
    int count = out.size();
    if (count != size) {
        qCritical() << "Vault: random password create error! The error password is %1" << out;
        return false;
    }
    for (int i =0; i< count; ++i) {
        if (!((out[i] >= '0' && out[i] <= '9') || (out[i] >= 'a' && out[i] <= 'f'))) {
            qCritical() << "Vault: random password create error! The error password is %1" << out;
            return false;
        }
    }
    return true;
}

bool EventReceiver::isTpmSupportAlgo(const QString &algoName, bool *support)
{
    if (algoName.isEmpty())
        return false;

    TPMWork tpm;
    return tpm.isSupportAlgo(algoName, support);
}

bool EventReceiver::encrypyByTpm(const QString &hashAlgo, const QString &keyAlgo, const QString &keyPin, const QString &password, const QString &dirPath)
{
    TPMWork tpm;
    return tpm.encrypt(hashAlgo, keyAlgo, keyPin, password, dirPath);
}

bool EventReceiver::decryptByTpm(const QString &keyPin, const QString &dirPath, QString *pwd)
{
    TPMWork tpm;
    return tpm.decrypt(keyPin, dirPath, pwd);
}

bool EventReceiver::tpmIsAvailableProcess()
{
    TPMWork tpm;
    return tpm.checkTPMAvailbableByTools();
}

bool EventReceiver::getRandomByTpmProcess(int size, QString *output)
{
    TPMWork tpm;
    return tpm.getRandomByTools(size, output);
}

bool EventReceiver::isTpmSupportAlgoProcess(const QString &algoName, bool *support)
{
    TPMWork tpm;
    return tpm.isSupportAlgoByTools(algoName, support);
}

bool EventReceiver::encryptByTpmProcess(const QVariantMap &encryptParams)
{
    if (!encryptParams.contains(PropertyKey::kEncryptType))
            return false;

        int type = encryptParams.value(PropertyKey::kEncryptType).toInt();
        if (type != 1 && type != 2)
            return false;

        if (!encryptParams.contains(PropertyKey::kPrimaryHashAlgo)
                || !encryptParams.contains(PropertyKey::kPrimaryKeyAlgo)
                || !encryptParams.contains(PropertyKey::kMinorHashAlgo)
                || !encryptParams.contains(PropertyKey::kMinorKeyAlgo)
                || !encryptParams.contains(PropertyKey::kDirPath)
                || !encryptParams.contains(PropertyKey::kPlain)) {
            return false;
        }

        if (type == 1) {
            if (!encryptParams.contains(PropertyKey::kPcr)
                    || !encryptParams.contains(PropertyKey::kPcrBank)) {
                return false;
            }
        }

        if (type == 2) {
            if (!encryptParams.contains(PropertyKey::kPinCode)) {
                return false;
            }
        }

        EncryptParams params;
        params.primaryHashAlgo = encryptParams.value(PropertyKey::kPrimaryHashAlgo).toString();
        params.primaryKeyAlgo = encryptParams.value(PropertyKey::kPrimaryKeyAlgo).toString();
        params.minorHashAlgo = encryptParams.value(PropertyKey::kMinorHashAlgo).toString();
        params.minorKeyAlgo = encryptParams.value(PropertyKey::kMinorKeyAlgo).toString();
        params.dirPath = encryptParams.value(PropertyKey::kDirPath).toString();
        params.plain = encryptParams.value(PropertyKey::kPlain).toString();
        if (type == 1) {
            params.type = kTpmAndPcr;
            params.pcr = encryptParams.value(PropertyKey::kPcr).toString();
            params.pcr_bank = encryptParams.value(PropertyKey::kPcrBank).toString();
        } else if (type == 2) {
            params.type = kTpmAndPin;
            params.pinCode = encryptParams.value(PropertyKey::kPinCode).toString();
        } else {
            return false;
        }

        TPMWork tpm;
        return tpm.encryptByTools(params);
}

bool EventReceiver::decryptByTpmProcess(const QVariantMap &decryptParams, QString *pwd)
{
    if (!decryptParams.contains(PropertyKey::kEncryptType))
            return false;

        int type = decryptParams.value(PropertyKey::kEncryptType).toInt();
        if (type != 1 && type != 2)
            return false;

        if (!decryptParams.contains(PropertyKey::kPrimaryHashAlgo)
                || !decryptParams.contains(PropertyKey::kPrimaryKeyAlgo)
                || !decryptParams.contains(PropertyKey::kDirPath)) {
            return false;
        }

        if (type == 1) {
            if (!decryptParams.contains(PropertyKey::kPcr)
                    || !decryptParams.contains(PropertyKey::kPcrBank)) {
                return false;
            }
        }

        if (type == 2) {
            if (!decryptParams.contains(PropertyKey::kPinCode)) {
                return false;
            }
        }

        DecryptParams params;
        params.primaryHashAlgo = decryptParams.value(PropertyKey::kPrimaryHashAlgo).toString();
        params.primaryKeyAlgo = decryptParams.value(PropertyKey::kPrimaryKeyAlgo).toString();
        params.dirPath = decryptParams.value(PropertyKey::kDirPath).toString();
        if (type == 1) {
            params.type = kTpmAndPcr;
            params.pcr = decryptParams.value(PropertyKey::kPcr).toString();
            params.pcr_bank = decryptParams.value(PropertyKey::kPcrBank).toString();
        } else if (type == 2) {
            params.type = kTpmAndPin;
            params.pinCode = decryptParams.value(PropertyKey::kPinCode).toString();
        } else {
            return false;
        }

        TPMWork tpm;
        return tpm.decryptByTools(params, pwd);
}

EventReceiver::EventReceiver(QObject *parent) : QObject(parent)
{
    initConnection();
}

void EventReceiver::initConnection()
{
    // slot event
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_TPMIsAvailable", this, &EventReceiver::tpmIsAvailable);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_GetRandomByTPM", this, &EventReceiver::getRandomByTpm);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_IsTPMSupportAlgo", this, &EventReceiver::isTpmSupportAlgo);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_EncryptByTPM", this, &EventReceiver::encrypyByTpm);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_DecryptByTPM", this, &EventReceiver::decryptByTpm);

    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_TPMIsAvailablePro", this, &EventReceiver::tpmIsAvailableProcess);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_GetRandomByTPMPro", this, &EventReceiver::getRandomByTpmProcess);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_IsTPMSupportAlgoPro", this, &EventReceiver::isTpmSupportAlgoProcess);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_EncryptByTPMPro", this, &EventReceiver::encryptByTpmProcess);
    dpfSlotChannel->connect("dfmplugin_encrypt_manager", "slot_DecryptByTPMPro", this, &EventReceiver::decryptByTpmProcess);
}
