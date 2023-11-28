// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DISKENCRYPTMENUSCENE_H
#define DISKENCRYPTMENUSCENE_H

#include "gui/encryptparamsinputdialog.h"

#include <dfm-base/interfaces/abstractmenuscene.h>
#include <dfm-base/interfaces/abstractscenecreator.h>

#include <dfm-mount/dmount.h>

#include <QUrl>

class QAction;

namespace dfmplugin_diskenc {

class DiskEncryptMenuCreator : public dfmbase::AbstractSceneCreator
{
    Q_OBJECT
    // AbstractSceneCreator interface
public:
    virtual dfmbase::AbstractMenuScene *create() override;
    static inline QString name()
    {
        return "DiskEncryptMenu";
    }
};

class DiskEncryptMenuScene : public dfmbase::AbstractMenuScene
{
    Q_OBJECT
public:
    explicit DiskEncryptMenuScene(QObject *parent = nullptr);

    // AbstractMenuScene interface
public:
    virtual QString name() const override;
    virtual bool initialize(const QVariantHash &params) override;
    virtual bool create(QMenu *parent) override;
    virtual bool triggered(QAction *action) override;
    virtual void updateState(QMenu *parent) override;

protected:
    static void encryptDevice(const DeviceEncryptParam &param);
    static void deencryptDevice(const DeviceEncryptParam &param);
    static void changePassphrase(const DeviceEncryptParam &param);
    static void unlockDevice(const QString &dev);

    static void doEncryptDevice(const DeviceEncryptParam &param);
    static void doDecryptDevice(const DeviceEncryptParam &param);
    static void doChangePassphrase(const QString &dev, const QString oldPass, const QString &newPass, bool validateByRec);

    static void onUnlocked(bool ok, dfmmount::OperationErrorInfo, QString);
    static void onMounted(bool ok, dfmmount::OperationErrorInfo, QString);

    void unmountBefore(const std::function<void(const DeviceEncryptParam &)> &after);
    enum OpType { kUnmount,
                  kLock };
    static void onUnmountError(OpType t, const QString &dev, const dfmmount::OperationErrorInfo &err);

private:
    QMap<QString, QAction *> actions;

    bool itemEncrypted { false };
    bool selectionMounted { false };
    QVariantHash selectedItemInfo;

    DeviceEncryptParam param;
};

}

#endif   // DISKENCRYPTMENUSCENE_H
