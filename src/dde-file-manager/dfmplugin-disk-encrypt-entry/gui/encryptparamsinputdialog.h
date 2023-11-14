// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef ENCRYPTPARAMSINPUTDIALOG_H
#define ENCRYPTPARAMSINPUTDIALOG_H

#include <dtkwidget_global.h>
#include <DDialog>

DWIDGET_BEGIN_NAMESPACE
class DPasswordEdit;
class DFileChooserEdit;
class DComboBox;
class DLineEdit;
DWIDGET_END_NAMESPACE

class QLabel;
class QStackedLayout;
class QLayout;

namespace dfmplugin_diskenc {

enum SecKeyType {
    kPasswordOnly,
    kTPMAndPIN,
    kTPMOnly,
};

struct ParamsInputs
{
    QString devDesc;
    QString uuid;
    SecKeyType type;
    QString key;
    QString exportPath;
    bool initOnly;
};

class EncryptParamsInputDialog : public DTK_WIDGET_NAMESPACE::DDialog
{
    Q_OBJECT
public:
    explicit EncryptParamsInputDialog(const QString &dev, QWidget *parent = nullptr);
    ParamsInputs getInputs();

protected:
    void initUi();
    void initConn();
    QWidget *createPasswordPage();
    QWidget *createExportPage();
    QWidget *createConfirmLayout();
    bool validatePassword();
    bool validateExportPath();
    void setPasswordInputVisible(bool visible);

protected Q_SLOTS:
    void onButtonClicked(int idx);
    void onPageChanged(int page);
    void onEncTypeChanged(int type);

private:
    bool encryptByTpm(const QString &deviceName);
    bool tpmAlgoChoice(QString *hashAlgo, QString *keyAlgo);

    DTK_WIDGET_NAMESPACE::DComboBox *encType { nullptr };
    DTK_WIDGET_NAMESPACE::DPasswordEdit *encKeyEdit1 { nullptr };
    DTK_WIDGET_NAMESPACE::DPasswordEdit *encKeyEdit2 { nullptr };

    QLabel *keyHint1 { nullptr };
    QLabel *keyHint2 { nullptr };
    QLabel *pinOnlyHint { nullptr };

    DTK_WIDGET_NAMESPACE::DFileChooserEdit *keyExportInput { nullptr };

    QStackedLayout *pagesLay { nullptr };

    QString device;
    QString tpmPassword;
};

}
#endif   // ENCRYPTPARAMSINPUTDIALOG_H