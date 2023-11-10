// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dfmplugin_disk_encrypt_global.h"
#include "encryptparamsinputdialog.h"
#include "utils/encryptutils.h"

#include <QVBoxLayout>
#include <QToolTip>
#include <QLabel>
#include <QFormLayout>
#include <QStackedLayout>
#include <QDebug>
#include <QFutureWatcher>
#include <QEventLoop>
#include <QtConcurrent/QtConcurrent>
#include <QAbstractButton>

#include <DDialog>
#include <DPasswordEdit>
#include <DComboBox>
#include <DFileChooserEdit>
#include <DSpinner>

using namespace dfmplugin_diskenc;
DWIDGET_USE_NAMESPACE

enum StepPage {
    kPasswordInputPage,
    kExportKeyPage,
    kConfirmPage,
};

EncryptParamsInputDialog::EncryptParamsInputDialog(const QString &dev, QWidget *parent)
    : DTK_WIDGET_NAMESPACE::DDialog(parent), device(dev)
{
    initUi();
    initConn();
}

ParamsInputs EncryptParamsInputDialog::getInputs()
{
    QString password;
    if (kTPMAndPIN == encType->currentIndex() || kTPMOnly == encType->currentIndex()) {
        password = tpmPassword;
        tpmPassword.clear();
    } else if (kPasswordOnly == encType->currentIndex()) {
        password = encKeyEdit1->text();
    }

    return { device,
             "",
             static_cast<SecKeyType>(encType->currentIndex()),
             password,
             keyExportInput->text() };
}

void EncryptParamsInputDialog::initUi()
{
    clearContents();
    setOnButtonClickedClose(false);
    setFixedSize(472, 304);
    setIcon(QIcon::fromTheme("drive-harddisk"));

    QWidget *center = new QWidget(this);
    center->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    addContent(center);

    pagesLay = new QStackedLayout(this);
    center->setLayout(pagesLay);

    pagesLay->addWidget(createPasswordPage());
    pagesLay->addWidget(createExportPage());
    pagesLay->addWidget(createConfirmLayout());

    onPageChanged(kPasswordInputPage);

    // for ui debugging
    //    setStyleSheet("border: 1px solid red;");
    //    center->setObjectName("center");
    //    center->setStyleSheet("QWidget#center{border: 1px solid red;}");
}

void EncryptParamsInputDialog::initConn()
{
    connect(pagesLay, &QStackedLayout::currentChanged,
            this, &EncryptParamsInputDialog::onPageChanged);
    connect(this, &EncryptParamsInputDialog::buttonClicked,
            this, &EncryptParamsInputDialog::onButtonClicked);
    connect(encType, static_cast<void (DComboBox::*)(int)>(&DComboBox::currentIndexChanged),
            this, &EncryptParamsInputDialog::onEncTypeChanged);
}

QWidget *EncryptParamsInputDialog::createPasswordPage()
{
    QWidget *wid = new QWidget(this);
    QFormLayout *lay = new QFormLayout(this);
    wid->setLayout(lay);

    encType = new DComboBox(this);
    encType->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    lay->addRow(tr("Encrypt type"), encType);

    keyHint1 = new QLabel(this);
    encKeyEdit1 = new DPasswordEdit(this);
    keyHint1->setMinimumWidth(66);
    lay->addRow(keyHint1, encKeyEdit1);

    keyHint2 = new QLabel(this);
    encKeyEdit2 = new DPasswordEdit(this);
    lay->addRow(keyHint2, encKeyEdit2);

    pinOnlyHint = new QLabel(tr("User access to the partition is automatically "
                                "unlocked without password checking."));
    pinOnlyHint->setWordWrap(true);
    lay->addRow("", pinOnlyHint);
    auto font = pinOnlyHint->font();
    font.setPixelSize(12);
    pinOnlyHint->setFont(font);

    encType->addItems({ tr("Unlocked by password"),
                        tr("Use PIN code to unlock on this computer (recommended)"),
                        tr("Automatic unlocking on this computer") });

    if (!tpm_utils::hasTPM()) {
        encType->setItemData(kTPMAndPIN, QVariant(0), Qt::UserRole - 1);
        encType->setItemData(kTPMOnly, QVariant(0), Qt::UserRole - 1);

        encType->setCurrentIndex(kPasswordOnly);
        onEncTypeChanged(kPasswordOnly);
    } else {
        encType->setCurrentIndex(kTPMAndPIN);
        onEncTypeChanged(kTPMAndPIN);
    }

    return wid;
}

QWidget *EncryptParamsInputDialog::createExportPage()
{
    QVBoxLayout *lay = new QVBoxLayout(this);
    QWidget *wid = new QWidget(this);
    wid->setLayout(lay);
    lay->setMargin(0);

    QLabel *hint = new QLabel(tr("In special cases such as forgetting the password or the encryption hardware is damaged, "
                                 "you can decrypt the encrypted partition with the recovery key, please export it to "
                                 "a non-encrypted partition and keep it in a safe place!"),
                              this);
    hint->setWordWrap(true);
    hint->adjustSize();
    lay->addWidget(hint);
    hint->setAlignment(Qt::AlignCenter);

    keyExportInput = new DFileChooserEdit(this);
    keyExportInput->setFileMode(QFileDialog::DirectoryOnly);
    lay->addWidget(keyExportInput);

    keyExportInput->setPlaceholderText(tr("Please select a non-encrypted partition as the key file export path."));

    return wid;
}

QWidget *EncryptParamsInputDialog::createConfirmLayout()
{
    QVBoxLayout *lay = new QVBoxLayout(this);
    QWidget *wid = new QWidget(this);
    wid->setLayout(lay);
    lay->setMargin(0);

    QLabel *hint = new QLabel(tr("After clicking \"Confirm encryption\", "
                                 "enter the user password to finish encrypting the \"%1\" partition.")
                                      .arg(device),
                              this);
    hint->setWordWrap(true);
    hint->adjustSize();
    hint->setAlignment(Qt::AlignCenter);

    lay->addWidget(hint);
    return wid;
}

bool EncryptParamsInputDialog::validatePassword()
{
    if (pagesLay->currentIndex() != kPasswordInputPage)
        return false;

    if (encType->currentIndex() == kTPMOnly)
        return true;

    auto showText = [this](const QString &t, const QPoint &p) {
        QToolTip::showText(getContent(0)->mapToGlobal(p), t, this);
    };

    QString pwd1 = encKeyEdit1->text().trimmed();
    QString pwd2 = encKeyEdit2->text().trimmed();

    if (pwd1.isEmpty()) {
        showText(tr("Empty"), encKeyEdit1->pos());
        return false;
    }

    if (pwd2.isEmpty()) {
        showText(tr("Empty"), encKeyEdit2->pos());
        return false;
    }

    QList<QRegularExpression> regx {
        QRegularExpression { R"([A-Z])" },
        QRegularExpression { R"([a-z])" },
        QRegularExpression { R"([0-9])" },
        QRegularExpression { R"([^A-Za-z0-9])" }
    };

    int factor = 0;
    std::for_each(regx.cbegin(), regx.cend(), [&factor, pwd1](const QRegularExpression &reg) {
        if (pwd1.contains(reg))
            factor += 1;
    });

    if (factor < 3 || pwd1.length() < 8) {
        showText(tr("Not safe"), encKeyEdit1->pos());
        return false;
    }

    if (pwd1 != pwd2) {
        showText(tr("Not equal"), encKeyEdit2->pos());
        return false;
    }

    return true;
}

bool EncryptParamsInputDialog::validateExportPath()
{
    // TODO(xust):
    return true;
}

void EncryptParamsInputDialog::setPasswordInputVisible(bool visible)
{
    keyHint1->setVisible(visible);
    keyHint2->setVisible(visible);
    encKeyEdit1->setVisible(visible);
    encKeyEdit2->setVisible(visible);

    pinOnlyHint->setVisible(!visible);
}

void EncryptParamsInputDialog::onButtonClicked(int idx)
{
    qDebug() << "button clicked:" << idx << "page: " << pagesLay->currentIndex();

    int currPage = pagesLay->currentIndex();
    if (currPage == kPasswordInputPage) {
        if (validatePassword())
            pagesLay->setCurrentIndex(config_utils::exportKeyEnabled() ? kExportKeyPage : kConfirmPage);
    } else if (currPage == kExportKeyPage) {
        if (idx == 0) {
            pagesLay->setCurrentIndex(kPasswordInputPage);
        } else if (idx == 1 && validateExportPath()) {
            pagesLay->setCurrentIndex(kConfirmPage);
        }
    } else if (currPage == kConfirmPage) {
        qDebug() << "confirm encrypt device: " << device;
        if (encType->currentIndex() == kTPMAndPIN || encType->currentIndex() == kTPMOnly) {
            if (!encryptByTpm(device))
                return;
        }
        accept();
    } else {
        qWarning() << "button triggered in wrong page!" << currPage << idx;
    }
}

void EncryptParamsInputDialog::onPageChanged(int page)
{
    if (page > kConfirmPage && page < kPasswordInputPage) {
        qWarning() << "invalid page index!" << page;
        return;
    }

    pagesLay->setCurrentIndex(page);
    clearButtons();
    if (page == kPasswordInputPage) {
        addButton(tr("Next"));
        setTitle(tr("Setting the unlocking method"));
    } else if (page == kExportKeyPage) {
        addButton(tr("Previous"));
        addButton(tr("Next"), true, ButtonType::ButtonRecommend);
        setTitle(tr("Export Recovery Key"));
    } else if (page == kConfirmPage) {
        addButton(tr("Confrim encrypt"));
        setTitle(tr("Partitioning Encryption"));
    }
}

void EncryptParamsInputDialog::onEncTypeChanged(int type)
{
    QString filed1 = tr("Set %1");
    QString filed2 = tr("Repeat %1");
    QString placeholder1 = tr("%1 at least 8 digits with A-Z, a-z, 0-9 and symbols");
    QString placeholder2 = tr("Please enter the %1 again");

    if (type == kPasswordOnly) {
        setPasswordInputVisible(true);
        keyHint1->setText(filed1.arg(tr("password")));
        keyHint2->setText(filed2.arg(tr("password")));
        encKeyEdit1->setPlaceholderText(placeholder1.arg(tr("Password")));
        encKeyEdit2->setPlaceholderText(placeholder2.arg(tr("password")));
    } else if (type == kTPMAndPIN) {
        setPasswordInputVisible(true);
        keyHint1->setText(filed1.arg(tr("PIN")));
        keyHint2->setText(filed2.arg(tr("PIN")));
        encKeyEdit1->setPlaceholderText(placeholder1.arg(tr("PIN")));
        encKeyEdit2->setPlaceholderText(placeholder2.arg(tr("PIN")));
    } else if (type == kTPMOnly) {
        setPasswordInputVisible(false);
    } else {
        qWarning() << "wrong encrypt type!" << type;
    }
}

bool EncryptParamsInputDialog::encryptByTpm(const QString &deviceName)
{
    QString password { "" };
    if (!tpm_utils::getRandomByTPM(kPasswordSize, &password) || password.isEmpty()) {
        qCritical() << "TPM get random number failed!";
        return false;
    }

    const QString dirPath = kTPMKeyPath + deviceName;
    QDir dir(dirPath);
    if (!dir.exists())
        dir.mkpath(dirPath);

    if (getButton(0))
        getButton(0)->setEnabled(false);

    QString hashAlgo;
    QString keyAlgo;
    if (!tpmAlgoChoice(&hashAlgo, &keyAlgo)) {
        qCritical() << "TPM algo choice failed!";
        return false;
    }

    QVariantMap map {
        { "PropertyKey_PrimaryHashAlgo", hashAlgo },
        { "PropertyKey_PrimaryKeyAlgo", keyAlgo },
        { "PropertyKey_MinorHashAlgo", hashAlgo },
        { "PropertyKey_MinorKeyAlgo", keyAlgo },
        { "PropertyKey_DirPath", dirPath },
        { "PropertyKey_Plain", password },
    };
    if (encType->currentIndex() == kTPMOnly) {
        map.insert("PropertyKey_EncryptType", 1);
        map.insert("PropertyKey_Pcr", "7");
        map.insert("PropertyKey_PcrBank", hashAlgo);
    } else if (encType->currentIndex() == kTPMAndPIN) {
        map.insert("PropertyKey_EncryptType", 2);
        map.insert("PropertyKey_PinCode", encKeyEdit1->text());
    } else {
        return false;
    }
    QFutureWatcher<bool> watcher;
    QEventLoop loop;
    QFuture<bool> future = QtConcurrent::run([map] {
        return tpm_utils::encryptByTPM(map);
    });
    connect(&watcher, &QFutureWatcher<bool>::finished, this, [&watcher, &loop] {
        if (watcher.result())
            loop.exit(0);
        else
            loop.exit(-1);
    });
    watcher.setFuture(future);

    DSpinner spinner(this);
    spinner.setFixedSize(50, 50);
    spinner.move((width() - spinner.width()) / 2, (height() - spinner.height()) / 2);
    spinner.start();
    spinner.show();

    int re = loop.exec();
    bool result = (re == 0 ? true : false);
    if (!result) {
        qCritical() << "TPM encrypt failed!";
        if (getButton(0))
            getButton(0)->setEnabled(true);
        return false;
    }

    QSettings settings(dirPath + QDir::separator() + "algo.ini", QSettings::IniFormat);
    settings.setValue(kConfigKeyPriHashAlgo, QVariant(hashAlgo));
    settings.setValue(kConfigKeyPriKeyAlgo, QVariant(keyAlgo));

    if (getButton(0))
        getButton(0)->setEnabled(true);

    tpmPassword = password;

    qInfo() << "DEBUG INFORMATION>>>>>>>>>>>>>>>   create TPM pwd for device:"
            << device
            << password;

    return true;
}

bool EncryptParamsInputDialog::tpmAlgoChoice(QString *hashAlgo, QString *keyAlgo)
{
    bool re1 { false };
    bool re2 { false };
    tpm_utils::isSupportAlgoByTPM(kTPMHashAlgo, &re1);
    tpm_utils::isSupportAlgoByTPM(kTPMKeyAlgo, &re2);

    if (re1 && re2) {
        (*hashAlgo) = kTPMHashAlgo;
        (*keyAlgo) = kTPMKeyAlgo;
        return true;
    }

    re1 = false;
    re2 = false;
    tpm_utils::isSupportAlgoByTPM(kTCMHashAlgo, &re1);
    tpm_utils::isSupportAlgoByTPM(kTCMKeyAlgo, &re2);

    if (re1 && re2) {
        (*hashAlgo) = kTCMHashAlgo;
        (*keyAlgo) = kTCMKeyAlgo;
        return true;
    }

    return false;
}
