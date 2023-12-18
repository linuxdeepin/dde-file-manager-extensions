// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "pwdencrypt.h"

#include <QDebug>

#include <openssl/pem.h>

FILE_ENCRYPT_USE_NS

PwdEncrypt *PwdEncrypt::instance()
{
    static PwdEncrypt ins;
    return &ins;
}

PwdEncrypt::~PwdEncrypt()
{
    if (rsa) {
        RSA_free(rsa);
        rsa = nullptr;
    }
}

void PwdEncrypt::initKeys()
{
    if (rsa)
        return;
    rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);

    BIO *bioPrivKey = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bioPrivKey, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    char *privKeyBuf;
    long privKeyLen = BIO_get_mem_data(bioPrivKey, &privKeyBuf);
    privKey = QByteArray(privKeyBuf, privKeyLen);
    BIO_free(bioPrivKey);

    BIO *bioPubKey = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bioPubKey, rsa);
    char *pubKeyBuf;
    long pubKeyLen = BIO_get_mem_data(bioPubKey, &pubKeyBuf);
    pubKey = QByteArray(pubKeyBuf, pubKeyLen);
    BIO_free(bioPubKey);
}

QString PwdEncrypt::getPubKey() const
{
    return pubKey;
}

int PwdEncrypt::decrypt(const QString &input, QString *output)
{
    Q_ASSERT(rsa);
    Q_ASSERT(output);

    QByteArray cipher = QByteArray::fromBase64(input.toLocal8Bit());

    int rsaSize = RSA_size(rsa);
    unsigned char *decrypted = new unsigned char[rsaSize];
    int decryptedLen = RSA_private_decrypt(cipher.length(),
                                           reinterpret_cast<const unsigned char *>(cipher.data()),
                                           decrypted,
                                           rsa,
                                           RSA_PKCS1_PADDING);

    if (decryptedLen == -1) {
        delete[] decrypted;
        return -1;
    }

    QByteArray source(reinterpret_cast<char *>(decrypted), decryptedLen);
    *output = QString(source);
    delete[] decrypted;
    return 0;
}

PwdEncrypt::PwdEncrypt(QObject *parent)
    : QObject { parent }
{
    initKeys();
}
