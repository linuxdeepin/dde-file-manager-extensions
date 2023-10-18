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

bool EventReceiver::decryptByTpm(const QString &keyPin, const QString &dirPath, QString *psw)
{
    TPMWork tpm;
    return tpm.decrypt(keyPin, dirPath, psw);
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
}
