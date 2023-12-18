// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PWDENCRYPT_H
#define PWDENCRYPT_H

#include "daemonplugin_file_encrypt_global.h"

#include <QObject>
#include <QString>

#include <openssl/rsa.h>

FILE_ENCRYPT_BEGIN_NS

class PwdEncrypt : public QObject
{
    Q_OBJECT
public:
    static PwdEncrypt *instance();
    ~PwdEncrypt();

    void initKeys();
    QString getPubKey() const;
    int decrypt(const QString &input, QString *output);

private:
    explicit PwdEncrypt(QObject *parent = nullptr);

    RSA *rsa { nullptr };
    QString pubKey;
    QString privKey;
};

FILE_ENCRYPT_END_NS

#endif   // PWDENCRYPT_H
