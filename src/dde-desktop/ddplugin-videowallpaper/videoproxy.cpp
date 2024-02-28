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
#include "videoproxy.h"

#include "dfm-base/dfm_desktop_defines.h"

#include <QPaintEvent>
#include <QPainter>

using namespace ddplugin_videowallpaper;
DFMBASE_USE_NAMESPACE

#ifdef USE_LIBDMR

VideoProxy::VideoProxy(QWidget *parent) : dmr::PlayerWidget(parent)
{
    dmr::PlayerEngine &eng = engine();
    eng.setMute(true);

    auto pal = palette();
    pal.setBrush(backgroundRole(), Qt::black);
    setPalette(pal);

    // do not decode audio
    _engine->setBackendProperty("ao", "no");
    _engine->setBackendProperty("color", QVariant::fromValue(QColor(Qt::black)));
    _engine->setBackendProperty("keep-open", "yes");
    _engine->setBackendProperty("dmrhwdec-switch", true);

    connect(_engine, &dmr::PlayerEngine::stateChanged, this, &VideoProxy::playNext);
}

VideoProxy::~VideoProxy()
{
    stop();
}

void VideoProxy::setPlayList(const QList<QUrl> &list)
{
    playList = list;
    if (list.contains(current))
        return;

    _engine->stop();
    _engine->getplaylist()->clear();

    play();
}

void VideoProxy::play()
{
    if (playList.isEmpty())
        return;

    QUrl next;
    if (playList.contains(current))
        next = current;
    else
        next = playList.first();

    run = true;
    current = next;
    PlayerWidget::play(next);

    QString hd =_engine->getBackendProperty("hwdec").toString();
    fmDebug() << "play" << next << "hardward decode" << hd;
}

void VideoProxy::stop()
{
    run = false;
    _engine->stop();
}

void VideoProxy::playNext()
{
    auto stat = _engine->state();
    if (run && stat != dmr::PlayerEngine::Playing) {
        if (playList.isEmpty()) {
            _engine->getplaylist()->clear();
            current.clear();
            return;
        }

        // 循环播放
        if (playList.size() == 1 && stat == dmr::PlayerEngine::Paused) {
            engine().seekAbsolute(0);
            engine().pauseResume();
            return;
        }

        // 播放下一个
        int idx = playList.indexOf(current);
        if (idx < 0 || idx >= playList.size() - 1)
            idx = 0;
        else
            idx++;

        _engine->getplaylist()->clear();
        current = playList.at(idx);
        PlayerWidget::play(current);

        QString hd =_engine->getBackendProperty("hwdec").toString();
        fmDebug() << "play" << current << "hardward decode" << hd;
    }
}

#else

VideoProxy::VideoProxy(QWidget *parent) : QWidget(parent)
{
    auto pal = palette();
    pal.setColor(backgroundRole(), Qt::black);
    setPalette(pal);
    setAutoFillBackground(false);
}

VideoProxy::~VideoProxy()
{

}

void VideoProxy::updateImage(const QImage &img)
{
    image = img.scaled(size() * devicePixelRatioF(), Qt::KeepAspectRatio);
    image.setDevicePixelRatio(devicePixelRatioF());
    update();
}

void VideoProxy::paintEvent(QPaintEvent *e)
{
    QPainter pa(this);
    auto fill = QRect(QPoint(0,0), size());
    pa.fillRect(fill, palette().background());

    if (image.isNull())
        return;
    QSize tar = image.size() / devicePixelRatioF();

    int x = (fill.width() - tar.width()) / 2.0;
    int y = (fill.height() - tar.height()) / 2.0;
    x = x < 0 ? 0 : x;
    y = y < 0 ? 0 : y;

    pa.drawImage(x, y, image);
}

#endif
