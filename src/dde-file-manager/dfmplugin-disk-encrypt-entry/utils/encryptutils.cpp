// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "encryptutils.h"

#include <dconfig.h>
#include <fstab.h>

using namespace dfmplugin_diskenc;

bool encrypt_utils::hasTPM()
{
    // TODO(xust): impl me
    return true;
}

bool config_utils::exportKeyEnabled()
{
    auto cfg = Dtk::Core::DConfig::create("org.deepin.dde.file-manager",
                                          "org.deepin.dde.file-manager.diskencrypt");
    cfg->deleteLater();
    return cfg->value("allowExportEncKey", true).toBool();
}

QString config_utils::cipherType()
{
    auto cfg = Dtk::Core::DConfig::create("org.deepin.dde.file-manager",
                                          "org.deepin.dde.file-manager.diskencrypt");
    cfg->deleteLater();
    return cfg->value("encryptAlgorithm", "sm4").toString();
}

bool fstab_utils::isFstabItem(const QString &mpt)
{
    if (mpt.isEmpty())
        return false;

    bool fstabed { false };
    struct fstab *fs;
    setfsent();
    while ((fs = getfsent()) != nullptr) {
        QString path = fs->fs_file;
        if (mpt == path) {
            fstabed = true;
            break;
        }
    }
    endfsent();
    return fstabed;
}
