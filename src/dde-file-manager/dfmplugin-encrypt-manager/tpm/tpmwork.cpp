// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "tpmwork.h"

#include <QLibrary>
#include <QDebug>
#include <QFile>
#include <QDir>

#include <fstream>

inline constexpr int kTpmOutTextMaxSize { 3000 };
inline constexpr char kTpmLibName[] { "libutpm2.so" };
inline constexpr char kTpmEncryptFileName[] { "tpm_encrypt.txt" };


DPENCRYPTMANAGER_USE_NAMESPACE

TPMWork::TPMWork(QObject *parent)
    : QObject(parent)
    , tpmLib(new QLibrary(kTpmLibName))
{
    if (!tpmLib->load())
        qWarning() << "Vault: load utpm2 failed, the error is " << tpmLib->errorString();
}

TPMWork::~TPMWork()
{
    if (tpmLib) {
        tpmLib->unload();
        delete tpmLib;
        tpmLib = nullptr;
    }
}

bool TPMWork::checkTPMAvailable()
{
    if (!tpmLib->isLoaded())
        return false;

    QString output;
    return getRandom(2, &output);
}

bool TPMWork::getRandom(int size, QString *output)
{
    if (!tpmLib->isLoaded())
        return false;

    if (size % 2 != 0 || size < 2 || size > 64) {
        qCritical() << "Vault: random size must be even and greater than or equal to 2 and less than or equal to 64!";
        return false;
    }

    typedef bool (*p_get_random)(uint16_t *size, uint8_t ranbytes[]);
    p_get_random utpm2_get_random = (p_get_random) tpmLib->resolve("utpm2_get_random");
    if (utpm2_get_random) {
        uint16_t len = size / 2;
        uint8_t *random = (uint8_t *)malloc(sizeof(uint8_t) * len);
        memset(random, 0, sizeof(uint8_t) * len);
        if (utpm2_get_random(&len, random)) {
            char *out = (char *)malloc(sizeof(uint8_t) * size + 1);
            memset(out, 0, sizeof(uint8_t) * size + 1);
            for (size_t i = 0; i < len; ++i) {
                sprintf(out + (i * 2), "%02x", random[i]);
            }
            *output = QString(out);
            free(random);
            free(out);
            return true;
        }
    }
    return false;
}

bool TPMWork::isSupportAlgo(const QString &algoName, bool *support)
{
    if (!tpmLib->isLoaded())
        return false;

    typedef bool (*p_check_algo)(const char *alg);
    p_check_algo utpm2_check_algo = (p_check_algo) tpmLib->resolve("utpm2_check_alg");
    if (utpm2_check_algo) {
        QByteArray arAlgoName = algoName.toUtf8();
        if (utpm2_check_algo(arAlgoName.data())) {
            *support = true;
        } else {
            *support = false;
        }
        return true;
    }

    return false;
}

bool TPMWork::initTpm2(const QString &hashAlgo, const QString &keyAlgo, const QString &keyPin, const QString &dirPath)
{
    if (!tpmLib->isLoaded())
        return false;

    typedef bool (*p_init)(char *algdetail, char *galg, const char *auth, const char *dir);
    p_init utpm2_init = (p_init)tpmLib->resolve("utpm2_init");
    if (utpm2_init) {
        QByteArray arKeyAlgo = keyAlgo.toUtf8();
        QByteArray arHashAlgo = hashAlgo.toUtf8();
        QByteArray arKeyPin = keyPin.toUtf8();
        QByteArray arDir = dirPath.toUtf8();
        if (utpm2_init(arKeyAlgo.data(), arHashAlgo.data(), arKeyPin.data(), arDir.data())) {
            return true;
        } else {
            qCritical() << "Vault: utpm2_init return false!";
        }
    } else {
        qCritical() << "Vault: resolve utpm2_init failed!";
    }
    return false;
}

bool TPMWork::encrypt(const QString &hashAlgo, const QString &keyAlgo, const QString &keyPin, const QString &password, const QString &dirPath)
{
    if (!initTpm2(hashAlgo, keyAlgo, keyPin, dirPath)) {
        return false;
    }

    typedef int (*p_encrypt_decrypt)(const char *dir, bool isdecrypt, const char *auth, uint8_t inbytes[], uint8_t outbytes[], uint16_t *size);
    p_encrypt_decrypt utpm2_encrypt_decrypt = (p_encrypt_decrypt) tpmLib->resolve("utpm2_encrypt_decrypt");
    if (utpm2_encrypt_decrypt) {
        QByteArray arDir = dirPath.toUtf8();
        QByteArray arKeyPin = keyPin.toUtf8();
        QByteArray arrPassword = password.toUtf8();
        uint16_t len = static_cast<uint16_t>(arrPassword.size());
        uint8_t *inbuffer = reinterpret_cast<uint8_t*>(arrPassword.data());
        uint8_t out_text[kTpmOutTextMaxSize] = { 0 };
        if (utpm2_encrypt_decrypt(arDir.data(), false, arKeyPin.data(), inbuffer, out_text, &len)) {
            QFile file(dirPath + QDir::separator() + kTpmEncryptFileName);
            if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                file.write(reinterpret_cast<const char*>(out_text), len);
                file.close();
                return true;
            } else {
                qCritical() << "Vault: open encrypt file failed!";
            }
        } else {
            qCritical() << "Vault: utpm2_encry_decrypt return false!";
        }
    } else {
        qCritical() << "Vault: resolve utpm2_encry_decrypt failed!";
    }
    return false;
}

bool TPMWork::decrypt(const QString &keyPin, const QString &dirPath, QString *psw)
{
    if (!tpmLib->isLoaded())
        return false;

    typedef int (*p_encrypt_decrypt)(const char *dir, bool isdecrypt, const char *auth, uint8_t inbytes[], uint8_t outbytes[], uint16_t *size);
    p_encrypt_decrypt utpm2_encrypt_decrypt = (p_encrypt_decrypt) tpmLib->resolve("utpm2_encrypt_decrypt");
    if (utpm2_encrypt_decrypt) {
        QByteArray arDir = QString(dirPath).toUtf8();
        QByteArray arKeyPin = keyPin.toUtf8();
        QFile file(dirPath + QDir::separator() + kTpmEncryptFileName);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QByteArray ciphertext = file.readAll();
            file.close();
            uint16_t len = static_cast<uint16_t>(ciphertext.size());
            uint8_t out_text[kTpmOutTextMaxSize] = { 0 };
            uint8_t *inbuffer = reinterpret_cast<uint8_t*>(ciphertext.data());
            if (utpm2_encrypt_decrypt(arDir.data(), true, arKeyPin.data(), inbuffer, out_text, &len)) {
                *psw = QString::fromUtf8(reinterpret_cast<const char*>(out_text), len);
                return true;
            } else {
                qCritical() << "Vault: utpm2_encry_decrypt return failed!";
            }
        } else {
            qCritical() << "Vault: open encrypt file failed!";
        }
    } else {
        qCritical() << "Vault: resolve utpm2_encry_decrypt failed!";
    }
    return false;
}

bool TPMWork::encryptByTools(const EncryptParams &params)
{
    const std::string plain  = params.plain.toStdString();

    const std::string pinCode = params.pinCode.toStdString();

    const std::string pcr = params.pcr.toStdString();
    const std::string pcr_bank = params.pcr_bank.toStdString();

    const std::string primary_key_alg = params.primaryKeyAlgo.toStdString();
    const std::string primary_hash_alg = params.primaryHashAlgo.toStdString();
    const std::string minor_key_alg = params.minorKeyAlgo.toStdString();
    const std::string minor_hash_alg = params.minorHashAlgo.toStdString();

    const std::string basePath = params.dirPath.toStdString();

    const std::string plainPath = basePath + "/plain.dat";
    const std::string ivPath = basePath + "/iv.bin";

    const std::string sessionPath = basePath + "/session.dat";
    const std::string policyPath = basePath + "/policy.dat";
    const std::string primaryCtxPath = basePath + "/primary.ctx";
    const std::string pubKeyPath = basePath + "/key.pub";
    const std::string priKeyPath = basePath + "/key.priv";
    const std::string keyNamePath = basePath + "/key.name";
    const std::string keyCtxPath = basePath + "/key.ctx";
    const std::string cipherPath = basePath + "/cipher.out";

    const std::string pcrPath = basePath + "/pcr_val.bin";

    // generate plain & iv
    if (std::system(("echo " + plain + " > " + plainPath).c_str()))
        return false;
    if (std::system(("tpm2_getrandom -o " + ivPath + " 16").c_str()))
        return false;

    // set policy
    if (std::system(("tpm2_startauthsession -S " + sessionPath + " -g " + primary_hash_alg + " -G " + primary_key_alg).c_str()))
        return false;
    if (params.type == kTpmAndPcr) {
        if (std::system(("tpm2_pcrread " + pcr_bank + ":" + pcr + " -o " + pcrPath).c_str()))
            return false;
        if (std::system(("tpm2_policypcr -S " + sessionPath + " -l " + pcr_bank + ":" + pcr + " -L " + policyPath + " -f " + pcrPath).c_str()))
            return false;
    } else if (params.type == kTpmAndPin) {
        if (std::system(("tpm2_policypassword -S " + sessionPath + " -L " + policyPath).c_str()))
            return false;
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }
    if (std::system(("tpm2_flushcontext " + sessionPath).c_str()))
        return false;

    // generate keys
    if (std::system(("tpm2_createprimary -C o -g " + primary_hash_alg + " -G " + primary_key_alg + " -c " + primaryCtxPath).c_str()))
        return false;
    if (params.type == kTpmAndPcr) {
        if (std::system(("tpm2_create -g " + minor_hash_alg + " -G " + minor_key_alg + " -u " + pubKeyPath + " -r " + priKeyPath + " -C " + primaryCtxPath + " -L " + policyPath).c_str()))
            return false;
    } else if (params.type == kTpmAndPin) {
        if (std::system(("tpm2_create -g " + minor_hash_alg + " -G " + minor_key_alg + " -u " + pubKeyPath + " -r " + priKeyPath + " -C " + primaryCtxPath + " -L " + policyPath + " -p " + pinCode).c_str()))
            return false;
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }
    if (std::system(("tpm2_load -C " + primaryCtxPath + " -u " + pubKeyPath + " -r " + priKeyPath + " -n " + keyNamePath + " -c " + keyCtxPath).c_str()))
        return false;

    // generate cipher
    if (std::system(("tpm2_startauthsession --policy-session -S " + sessionPath + " -g " + primary_hash_alg + " -G " + primary_key_alg).c_str()))
        return false;
    if (params.type == kTpmAndPcr) {
        if (std::system(("tpm2_pcrread " + pcr_bank + ":" + pcr + " -o " + pcrPath).c_str()))
            return false;
        if (std::system(("tpm2_policypcr -S " + sessionPath + " -l " + pcr_bank + ":" + pcr + " -f " + pcrPath).c_str()))
            return false;
        if (std::system(("tpm2_encryptdecrypt -Q --iv " + ivPath + " -c " + keyCtxPath + " -o " + cipherPath + " " + plainPath + " -p session:" + sessionPath).c_str()))
            return false;
    } else if (params.type == kTpmAndPin) {
        if (std::system(("tpm2_policypassword -S " + sessionPath + " -L " + policyPath).c_str()))
            return false;
        if (std::system(("tpm2_encryptdecrypt -Q --iv " + ivPath + " -c " + keyCtxPath + " -o " + cipherPath + " " + plainPath + " -p session:" + sessionPath + "+" + pinCode).c_str()))
            return false;
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }
    if (std::system(("tpm2_flushcontext " + sessionPath).c_str()))
        return false;

    // clean files
    if (params.type == kTpmAndPcr) {
        if (std::system(("rm " + keyCtxPath + " " + keyNamePath + " " + plainPath + " " + policyPath + " " + primaryCtxPath + " " + sessionPath + " " + pcrPath).c_str()))
            return false;
    } else if (params.type == kTpmAndPin) {
        if (std::system(("rm " + keyCtxPath + " " + keyNamePath + " " + plainPath + " " + policyPath + " " + primaryCtxPath + " " + sessionPath).c_str()))
            return false;
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }

    return true;
}

bool TPMWork::decryptByTools(const DecryptParams &params, QString *pwd)
{
    const std::string pinCode = params.pinCode.toStdString();
    std::string pcr = params.pcr.toStdString();
    std::string pcr_bank = params.pcr_bank.toStdString();
    const std::string primary_key_alg = params.primaryKeyAlgo.toStdString();
    const std::string primary_hash_alg = params.primaryHashAlgo.toStdString();

    const std::string basePath = params.dirPath.toStdString();

    const std::string cipherPath = basePath + "/cipher.out";
    const std::string ivPath = basePath + "/iv.bin";
    const std::string pubKeyPath = basePath + "/key.pub";
    const std::string priKeyPath = basePath + "/key.priv";

    const std::string sessionPath = basePath + "/session.dat";
    const std::string policyPath = basePath + "/policy.dat";
    const std::string primaryCtxPath = basePath + "/primary.ctx";
    const std::string keyNamePath = basePath + "/key.name";
    const std::string keyCtxPath = basePath + "/key.ctx";
    const std::string clearPath = basePath + "/clear.out";

    if (std::system(("tpm2_startauthsession --policy-session -S " + sessionPath + " -g " + primary_hash_alg + " -G " + primary_key_alg).c_str()))
        return false;
    if (params.type == kTpmAndPcr) {
        if (std::system(("tpm2_policypcr -S " + sessionPath + " -l " + pcr_bank + ":" + pcr).c_str()))
            return false;
    } else if (params.type == kTpmAndPin) {
        if (std::system(("tpm2_policypassword -S " + sessionPath + " -L " + policyPath).c_str()))
            return false;
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }
    if (std::system(("tpm2_createprimary -C o -g " + primary_hash_alg + " -G " + primary_key_alg + " -c " + primaryCtxPath).c_str()))
        return false;
    if (std::system(("tpm2_load -C " + primaryCtxPath + " -u " + pubKeyPath + " -r " + priKeyPath + " -n " + keyNamePath +  " -c " + keyCtxPath).c_str()))
        return false;
    if (params.type == kTpmAndPcr) {
        if (std::system(("tpm2_encryptdecrypt -Q --iv " + ivPath + " -c " + keyCtxPath + " -o " + clearPath + " " + cipherPath + " -p session:" + sessionPath).c_str()))
            return false;
    } else if (params.type == kTpmAndPin) {
        if (std::system(("tpm2_encryptdecrypt -Q --iv " + ivPath + " -c " + keyCtxPath + " -o " + clearPath + " " + cipherPath + " -p session:" + sessionPath + "+" + pinCode).c_str()))
            return false;
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }
    if (std::system(("tpm2_flushcontext " + sessionPath).c_str()))
        return false;

    std::ifstream plain_ifs(clearPath, std::ios_base::in);
    if (!plain_ifs.is_open())
        return false;
    std::string plain;
    plain_ifs >> plain;
    plain_ifs.close();

    (*pwd) = QString::fromStdString(plain);

    // clean files
    if (params.type == kTpmAndPcr) {
        std::system(("rm " + clearPath + " " + keyCtxPath + " " + keyNamePath + " " + primaryCtxPath + " " + sessionPath).c_str());
    } else if (params.type == kTpmAndPin) {
        std::system(("rm " + clearPath + " " + keyCtxPath + " " + keyNamePath + " " + policyPath + " " + primaryCtxPath + " " + sessionPath).c_str());
    } else {
        qCritical() << "Tpm type unkonw!";
        return false;
    }

    return true;
}


