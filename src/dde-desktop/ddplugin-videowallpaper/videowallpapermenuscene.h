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
#ifndef VIDEOWALLPAERMENUSCENE_H
#define VIDEOWALLPAERMENUSCENE_H

#include "dfm-base/interfaces/abstractmenuscene.h"
#include "dfm-base/interfaces/abstractscenecreator.h"

#include <QMap>

namespace ddplugin_videowallpaper {

namespace ActionID {
inline constexpr char kVideoWallpaper[] = "video-wallpaper";
}

class VideoWallpaerMenuCreator : public DFMBASE_NAMESPACE::AbstractSceneCreator
{
    Q_OBJECT
public:
    static QString name()
    {
        return "VideoWallpaperMenu";
    }
    DFMBASE_NAMESPACE::AbstractMenuScene *create() override;
};

class VideoWallpaperMenuScene : public DFMBASE_NAMESPACE::AbstractMenuScene
{
    Q_OBJECT
public:
    explicit VideoWallpaperMenuScene(QObject *parent = nullptr);
    QString name() const override;
    bool initialize(const QVariantHash &params) override;
    AbstractMenuScene *scene(QAction *action) const override;
    bool create(QMenu *parent) override;
    void updateState(QMenu *parent) override;
    bool triggered(QAction *action) override;
private:
    bool turnOn = false;
    bool onDesktop = false;
    bool isEmptyArea = false;
    QMap<QString, QAction *> predicateAction;   // id -- instance
    QMap<QString, QString> predicateName;   // id -- text
};
}

#endif // VIDEOWALLPAERMENUSCENE_H
