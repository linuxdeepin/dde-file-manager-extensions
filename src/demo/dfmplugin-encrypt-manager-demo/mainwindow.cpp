#include "mainwindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFile>
#include <QDir>

#include <dfm-framework/event/event.h>

Q_DECLARE_METATYPE(QString *)
Q_DECLARE_METATYPE(bool *)

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    initUi();
    initConnect();
}

void MainWindow::initUi()
{
    QWidget *mainWidget = new QWidget(this);
    QVBoxLayout *mainLay = new QVBoxLayout;
    mainWidget->setLayout(mainLay);

    editInput = new QLineEdit(mainWidget);

    textBrowser = new QTextBrowser(mainWidget);
    textBrowser->setReadOnly(true);

    QGridLayout *btnLay = new QGridLayout;
    btnCheckTpm = new QPushButton(tr("Check TPM"), mainWidget);
    btnCheckTcm = new QPushButton(tr("Check TCM"), mainWidget);
    btnGetRandom = new QPushButton(tr("Get Random"), mainWidget);
    btnCheckAlgo = new QPushButton(tr("Check Algo"), mainWidget);
    btnEncrypt = new QPushButton(tr("Encrypt"), mainWidget);
    btnDecrypt = new QPushButton(tr("Decrypt"), mainWidget);
    btnLay->addWidget(btnCheckTpm, 0, 0);
    btnLay->addWidget(btnCheckTcm, 0, 1);
    btnLay->addWidget(btnGetRandom, 0, 2);
    btnLay->addWidget(btnCheckAlgo, 0, 3);
    btnLay->addWidget(btnEncrypt, 1, 0);
    btnLay->addWidget(btnDecrypt, 1, 1);

    mainLay->addWidget(editInput);
    mainLay->addWidget(textBrowser);
    mainLay->addItem(btnLay);

    setCentralWidget(mainWidget);
    setMinimumSize(800, 500);
}

void MainWindow::initConnect()
{
    connect(btnCheckTpm, &QPushButton::clicked, this, [this]{
        bool result =  dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_TPMIsAvailable").toBool();
        if (result)
            textBrowser->append("TPM is available!");
        else
            textBrowser->append("TPM is not available!");
    });
    connect(btnCheckTcm, &QPushButton::clicked, this, [this]{

    });
    connect(btnGetRandom, &QPushButton::clicked, this, [this]{
        int size = editInput->text().toInt();
        QString out;
        bool result = dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_GetRandomByTPM", size, &out).toBool();
        if (result) {
            textBrowser->append(QString("Random is: %1").arg(out));
        } else {
            textBrowser->append("Get random failed!");
        }
    });
    connect(btnCheckAlgo, &QPushButton::clicked, this, [this]{
        const QString algoName = editInput->text();
        bool bSupport { false };
        bool result = dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_IsTPMSupportAlgo", algoName, &bSupport).toBool();
        if (result) {
            textBrowser->append(QString("The check result is %1!").arg(bSupport));
        } else {
            textBrowser->append("Check algo name failed!");
        }
    });
    connect(btnEncrypt, &QPushButton::clicked, this, [this]{
        const QString hashAlgo = "sha256";
        const QString keyAlgo = "aes";
        const QString keyPin = ""/*"12345678"*/;
        const QString password = "Qwer@1234";
        const QString dirPath = "/home/uos/gongheng/tmpTemp";
        bool result = dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_EncryptByTPM", hashAlgo, keyAlgo, keyPin, password, dirPath).toBool();
        if (result) {
            textBrowser->append("Encrypt success!");
            QFile file(dirPath + QDir::separator() + "tpm_encrypt.txt");
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray ciphertext = file.readAll();
                QByteArray baseCiphertext = ciphertext.toBase64();
                textBrowser->append("Cipher text: " + QString(baseCiphertext));
                file.close();
            }
            file.setFileName(dirPath + QDir::separator() + "key.priv");
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray priKey = file.readAll();
                QByteArray basePriKey = priKey.toBase64();
                textBrowser->append("Pri key: " + QString(basePriKey));
                file.close();
            }

            file.setFileName(dirPath + QDir::separator() + "key.pub");
            if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray pubKey = file.readAll();
                QByteArray basePubKey = pubKey.toBase64();
                textBrowser->append("Pub key: " + QString(basePubKey));
                file.close();
            }

        } else {
            textBrowser->append("Encrypt failed!");
        }
    });
    connect(btnDecrypt, &QPushButton::clicked, this, [this]{
        const QString keyPin = ""/*"12345678"*/;
        const QString dirPath = "/home/uos/gongheng/tmpTemp";
        QString password;
        bool result = dpfSlotChannel->push("dfmplugin_encrypt_manager", "slot_DecryptByTPM", keyPin, dirPath, &password).toBool();
        if (result) {
            textBrowser->append(QString("Password is: %1 !").arg(password));
        } else {
            textBrowser->append("Decrypt failed!");
        }
    });
}
