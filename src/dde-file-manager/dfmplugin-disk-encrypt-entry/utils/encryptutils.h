// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTUTILS_H
#define ENCRYPTUTILS_H

namespace dfmplugin_diskenc {
namespace encrypt_utils {
bool hasTPM();
bool exportKeyEnabled();
}   // namespace encrypt_utils
}   // namespace dfmplugin_diskenc

#endif   // ENCRYPTUTILS_H
