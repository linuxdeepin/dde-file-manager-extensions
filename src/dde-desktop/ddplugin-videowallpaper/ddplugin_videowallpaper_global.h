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
#ifndef DDPLUGIN_VIDEOWALLPAPER_GLOBAL_H
#define DDPLUGIN_VIDEOWALLPAPER_GLOBAL_H

#include <dfm-base/dfm_log_defines.h>

#define DDP_VIDEOWALLPAPER_NAMESPACE ddplugin_videowallpaper

#define DDP_VIDEOWALLPAPER_BEGIN_NAMESPACE namespace DDP_VIDEOWALLPAPER_NAMESPACE{
#define DDP_VIDEOWALLPAPER_END_NAMESPACE }
#define DDP_VIDEOWALLPAPER_USE_NAMESPACE using namespace DDP_VIDEOWALLPAPER_NAMESPACE;

DDP_VIDEOWALLPAPER_BEGIN_NAMESPACE

DFM_LOG_USE_CATEGORY(DDP_VIDEOWALLPAPER_NAMESPACE)

DDP_VIDEOWALLPAPER_END_NAMESPACE

#endif // DDPLUGIN_BACKGROUND_GLOBAL_H
