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
#ifndef WALLPAPERENGINE_P_H
#define WALLPAPERENGINE_P_H

#include "wallpaperengine.h"
#include "videoproxy.h"
#include "videosurface.h"

#include <QFileSystemWatcher>
#include <QUrl>

#ifndef USE_LIBDMR
#include <QtMultimedia/QMediaPlayer>
#include <QtMultimediaWidgets/QVideoWidget>
#include <QtMultimedia/QMediaPlaylist>
#endif

namespace ddplugin_videowallpaper {

class WallpaperEnginePrivate
{
public:
    explicit WallpaperEnginePrivate(WallpaperEngine *qq);
    inline QRect relativeGeometry(const QRect &geometry)
    {
        return QRect(QPoint(0, 0), geometry.size());
    }
#ifndef USE_LIBDMR
    static QList<QMediaContent> getVideos(const QString &path);
#else
    static QList<QUrl> getVideos(const QString &path);
#endif
public:
    VideoProxyPointer createWidget(QWidget *root);
    void setBackgroundVisible(bool v);
    QString sourcePath() const;
    QMap<QString, VideoProxyPointer> widgets;

    QFileSystemWatcher *watcher = nullptr;
#ifndef USE_LIBDMR
    QList<QMediaContent> videos;
    QMediaPlaylist *playlist = nullptr;
    QMediaPlayer *player = nullptr;
    VideoSurface *surface = nullptr;
#else
    QList<QUrl> videos;
#endif
private:
    WallpaperEngine *q;
};

}

#endif // WALLPAPERENGINE_P_H
