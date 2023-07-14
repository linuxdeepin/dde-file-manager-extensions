// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "plugin_diskencryptentry.h"
#include "menu/diskencryptmenuscene.h"

#include <QDebug>

static constexpr char kComputerPluginName[] { "dfmplugin_computer" };
static constexpr char kMenuPluginName[] { "dfmplugin_menu" };

using namespace dfmplugin_diskenc;

bool hasComputerMenuRegisted()
{
    return dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_Contains", "ComputerMenu").toBool();
}

void DiskEncryptEntry::initialize()
{
    qDebug() << "##########################################";
    qDebug() << "DiskEncryptEntry initialized";
    qDebug() << "##########################################";
}

bool DiskEncryptEntry::start()
{
    dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_RegisterScene", DiskEncryptMenuCreator::name(), new DiskEncryptMenuCreator);

    if (hasComputerMenuRegisted()) {
        dpfSlotChannel->push("dfmplugin_menu", "slot_MenuScene_Bind", DiskEncryptMenuCreator::name(), kComputerPluginName);
    } else {
        dpfSignalDispatcher->subscribe(kMenuPluginName, "signal_MenuScene_SceneAdded", this, &DiskEncryptEntry::onComputerMenuSceneAdded);
    }

    return true;
}

void DiskEncryptEntry::onComputerMenuSceneAdded(const QString &scene)
{
    if (scene == "ComputerMenu") {
        dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_Bind", DiskEncryptMenuCreator::name(), "ComputerMenu");
        dpfSignalDispatcher->unsubscribe("dfmplugin_menu", "signal_MenuScene_SceneAdded", this, &DiskEncryptEntry::onComputerMenuSceneAdded);
    }
}
