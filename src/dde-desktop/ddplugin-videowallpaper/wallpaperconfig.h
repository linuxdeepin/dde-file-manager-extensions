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
#ifndef WALLPAPERCONFIG_H
#define WALLPAPERCONFIG_H

#include <QObject>

namespace ddplugin_videowallpaper {

class WallpaperConfigPrivate;
class WallpaperConfig : public QObject
{
    Q_OBJECT
    friend class WallpaperConfigPrivate;
public:
    static WallpaperConfig *instance();
    void initialize();
    bool enable() const;
    void setEnable(bool);
signals:
    void changeEnableState(bool enable);
    void checkResource();
public slots:
private slots:
    void configChanged(const QString &key);
protected:
    explicit WallpaperConfig(QObject *parent = nullptr);
private:
    WallpaperConfigPrivate *d;
};

}

#define WpCfg WallpaperConfig::instance()

#endif // WALLPAPERCONFIG_H
