// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H
#define DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(DFMPLUGIN_DISK_ENCRYPT_LIBRARY)
#  define DFMPLUGIN_DISK_ENCRYPT_EXPORT Q_DECL_EXPORT
#else
#  define DFMPLUGIN_DISK_ENCRYPT_EXPORT Q_DECL_IMPORT
#endif

#endif // DFMPLUGIN_DISK_ENCRYPT_GLOBAL_H
