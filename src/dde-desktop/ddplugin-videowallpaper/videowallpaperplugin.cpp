/*
 * Copyright (C) 2022 Uniontech Software Technology Co., Ltd.
 *
 * Author:     zhangyu<zhangyub@uniontech.com>
 *
 * Maintainer: zhangyu<zhangyub@uniontech.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "videowallpaperplugin.h"
#include "wallpaperengine.h"

#include <QTranslator>

namespace ddplugin_videowallpaper {
DFM_LOG_REISGER_CATEGORY(DDP_VIDEOWALLPAPER_NAMESPACE)
}

DDP_VIDEOWALLPAPER_USE_NAMESPACE

VideoWallpaperPlugin::VideoWallpaperPlugin(QObject *parent) : Plugin()
{

}

void ddplugin_videowallpaper::VideoWallpaperPlugin::initialize()
{
#ifdef USE_LIBDMR
    // for libdmr
    setlocale(LC_NUMERIC, "C");
#endif
    // load translation
    auto trans = new QTranslator(this);
    if (trans->load(QString(":/translations/ddplugin-videowallpaper_%1.qm").arg(QLocale::system().name())))
        QCoreApplication::installTranslator(trans);
    else
        delete trans;
}

bool VideoWallpaperPlugin::start()
{
    engine = new WallpaperEngine();
    return engine->init();
}

void VideoWallpaperPlugin::stop()
{
    delete engine;
    engine = nullptr;
}
