// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DISKENCRYPTMENUSCENE_H
#define DISKENCRYPTMENUSCENE_H

#include <dfm-base/interfaces/abstractmenuscene.h>
#include <dfm-base/interfaces/abstractscenecreator.h>

#include "gui/encryptparamsinputdialog.h"

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

private:
    QUrl selectedItem;
    QString devDesc;
    QAction *actEncrypt { nullptr };
};

}

#endif   // DISKENCRYPTMENUSCENE_H
