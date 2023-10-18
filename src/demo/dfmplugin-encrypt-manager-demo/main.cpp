// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "mainwindow.h"

#include <QApplication>
#include <QDebug>

#include <dfm-framework/dpf.h>

inline constexpr char kPluginIID[] { "org.deepin.plugin.filemanager" };

static bool pluginsLoad()
{
    QStringList pluginsDirs;
    pluginsDirs.push_back("~/pluginsDir");
    QStringList blackNames {};
    DPF_NAMESPACE::LifeCycle::initialize({ kPluginIID }, pluginsDirs, blackNames);

    if (!DPF_NAMESPACE::LifeCycle::readPlugins())
        return false;

    if (!DPF_NAMESPACE::LifeCycle::loadPlugins())
        return false;

    return true;
}

int main(int argc, char *argv[])
{
    qputenv("QT_LOGGING_RULES", "*.info=true");

    QApplication a(argc, argv);

    if (!pluginsLoad()) {
        qCritical() << "Load plugin failed!";
        abort();
    }

    MainWindow window;
    window.show();

    return a.exec();
}
