// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef EVENTSHANDLER_H
#define EVENTSHANDLER_H

#include <QObject>
#include <QMap>

namespace dfmplugin_diskenc {
class EncryptProgressDialog;
class EncryptParamsInputDialog;
class EventsHandler : public QObject
{
    Q_OBJECT
public:
    static EventsHandler *instance();
    void bindDaemonSignals();
    void hookEvents();
    bool hasEnDecryptJob();
    bool isEncrypting(const QString &device);
    bool onAcquireDevicePwd(const QString &dev, QString *pwd, bool *giveup);

private Q_SLOTS:
    void onPreencryptResult(const QString &, const QString &, const QString &, int);
    void onEncryptResult(const QString &, const QString &, int);
    void onEncryptProgress(const QString &, const QString &, double);
    void onDecryptResult(const QString &, const QString &, const QString &, int);
    void onDecryptProgress(const QString &, const QString &, double);
    void onChgPassphraseResult(const QString &, const QString &, const QString &, int);
    void onRequestEncryptParams(const QVariantMap &encConfig);

    QString acquirePassphrase(const QString &dev, bool &cancelled);
    QString acquirePassphraseByPIN(const QString &dev, bool &cancelled);
    QString acquirePassphraseByTPM(const QString &dev, bool &cancelled);
    QString acquirePassphraseByRec(const QString &dev, bool &cancelled);

    void showPreEncryptError(const QString &device, const QString &devName, int code);
    void showDecryptError(const QString &device, const QString &devName, int code);
    void showChgPwdError(const QString &device, const QString &devName, int code);
    void showRebootOnPreencrypted(const QString &device, const QString &devName);
    void showRebootOnDecrypted(const QString &device, const QString &devName);

    void requestReboot();

private:
    explicit EventsHandler(QObject *parent = nullptr);

    QMap<QString, EncryptProgressDialog *> encryptDialogs;
    QMap<QString, EncryptProgressDialog *> decryptDialogs;
    QMap<QString, EncryptParamsInputDialog *> encryptInputs;
signals:
};
}
#endif   // EVENTSHANDLER_H
