// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "plugin_diskencryptentry.h"
#include "menu/diskencryptmenuscene.h"
#include "events/eventshandler.h"

#include <QTranslator>

using namespace dfmplugin_diskenc;

bool hasComputerMenuRegisted()
{
    return dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_Contains", QString(kComputerMenuSceneName)).toBool();
}

void DiskEncryptEntry::initialize()
{
    auto i18n = new QTranslator(this);
    i18n->load(QLocale(), "disk-encrypt", "_", "/usr/share/dde-file-manager/translations");
    QCoreApplication::installTranslator(i18n);
}

bool DiskEncryptEntry::start()
{
    dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_RegisterScene",
                         DiskEncryptMenuCreator::name(), new DiskEncryptMenuCreator);

    if (hasComputerMenuRegisted()) {
        dpfSlotChannel->push("dfmplugin_menu", "slot_MenuScene_Bind",
                             DiskEncryptMenuCreator::name(), QString(kComputerMenuSceneName));
    } else {
        dpfSignalDispatcher->subscribe(kMenuPluginName, "signal_MenuScene_SceneAdded",
                                       this, &DiskEncryptEntry::onComputerMenuSceneAdded);
    }

    EventsHandler::instance()->bindDaemonSignals();
    EventsHandler::instance()->hookEvents();

    return true;
}

void DiskEncryptEntry::onComputerMenuSceneAdded(const QString &scene)
{
    if (scene == "ComputerMenu") {
        dpfSlotChannel->push(kMenuPluginName, "slot_MenuScene_Bind",
                             DiskEncryptMenuCreator::name(), kComputerMenuSceneName);
        dpfSignalDispatcher->unsubscribe("dfmplugin_menu", "signal_MenuScene_SceneAdded",
                                         this, &DiskEncryptEntry::onComputerMenuSceneAdded);
    }
}
