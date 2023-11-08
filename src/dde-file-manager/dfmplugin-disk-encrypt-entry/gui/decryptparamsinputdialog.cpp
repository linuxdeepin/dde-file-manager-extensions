// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "decryptparamsinputdialog.h"

using namespace dfmplugin_diskenc;
DecryptParamsInputDialog::DecryptParamsInputDialog(const QString &device, QWidget *parent)
    : Dtk::Widget::DDialog(parent), devDesc(device)
{
    initUI();
}

QPair<QString, QString> DecryptParamsInputDialog::getInputs()
{
    return { devDesc, editor->text() };
}

void DecryptParamsInputDialog::setInputPIN(bool pin)
{
    if (pin)
        setTitle(tr("Please input TPM PIN of %1").arg(devDesc));
}

void DecryptParamsInputDialog::initUI()
{
    setTitle(tr("Please input passphrase of %1").arg(devDesc));
    editor = new Dtk::Widget::DPasswordEdit(this);
    addContent(editor);
    addButton(tr("Confirm"));
}
