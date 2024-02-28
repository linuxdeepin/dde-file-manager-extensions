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
#ifndef VIDEOPROXY_H
#define VIDEOPROXY_H

#include "ddplugin_videowallpaper_global.h"

#ifdef USE_LIBDMR
#include <player_widget.h>
#include <player_engine.h>
#include <compositing_manager.h>
#else
#include <QWidget>
#include <QtMultimedia/QMediaContent>

class QMediaPlayer;
class QVideoWidget;
class QMediaPlaylist;
#endif

namespace ddplugin_videowallpaper {

#ifdef USE_LIBDMR
class VideoProxy : public dmr::PlayerWidget
{
    Q_OBJECT
public:
    explicit VideoProxy(QWidget *parent = nullptr);
    ~VideoProxy();
    void setPlayList(const QList<QUrl> &list);
    void play();
    void stop();
protected slots:
    void playNext();
private:
    QList<QUrl> playList;
    QUrl current;
    bool run = false;
};

#else
class VideoProxy : public QWidget
{
    Q_OBJECT
public:
    explicit VideoProxy(QWidget *parent = nullptr);
    ~VideoProxy();
    void updateImage(const QImage &img);
protected:
    void paintEvent(QPaintEvent *) override;
private:
    QImage image;
};
#endif
typedef QSharedPointer<VideoProxy> VideoProxyPointer;

}

#endif // VIDEOPROXY_H
