// SPDX-FileCopyrightText: 2023 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
#include "diskencrypt.h"
#include "fsresize/fsresize.h"
#include "notification/notifications.h"

#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QFile>
#include <QLibrary>

#include <dfm-base/utils/finallyutil.h>
#include <dfm-mount/dmount.h>

#include <libcryptsetup.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <functional>

FILE_ENCRYPT_USE_NS

#define CHECK_INT(checkVal, msg, retVal)   \
    if ((checkVal) < 0) {                  \
        qWarning() << (msg) << (checkVal); \
        return retVal;                     \
    }
#define CHECK_BOOL(checkVal, msg, retVal) \
    if (!(checkVal)) {                    \
        qWarning() << (msg);              \
        return retVal;                    \
    }

// used to record current reencrypting device.
QString gCurrReencryptingDevice;
QString gCurrDecryptintDevice;
bool gInterruptEncFlag { false };

struct crypt_params_reencrypt *encryptParams()
{
    static struct crypt_params_luks2 reencLuks2
    {
        .sector_size = 512
    };

    static struct crypt_params_reencrypt reencParams
    {
        .mode = CRYPT_REENCRYPT_ENCRYPT,
        .direction = CRYPT_REENCRYPT_BACKWARD,
        .resilience = "datashift",
        .hash = "sha256",
        .data_shift = 32 * 1024,
        .max_hotzone_size = 0,
        .device_size = 0,
        .luks2 = &reencLuks2,
        .flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
    };
    return &reencParams;
}
struct crypt_params_reencrypt *decryptParams()
{
    static struct crypt_params_reencrypt params
    {
        .mode = CRYPT_REENCRYPT_DECRYPT,
        .direction = CRYPT_REENCRYPT_BACKWARD,
        .resilience = "checksum",
        .hash = "sha256",
        .data_shift = 0,
        .max_hotzone_size = 0,
        .device_size = 0
    };
    return &params;
}
struct crypt_params_reencrypt *resumeParams()
{
    static struct crypt_params_reencrypt params
    {
        .mode = CRYPT_REENCRYPT_REENCRYPT,
        .direction = CRYPT_REENCRYPT_FORWARD,
        .resilience = "checksum",
        .hash = "sha256",
        .max_hotzone_size = 0,
        .device_size = 0,
        .flags = CRYPT_REENCRYPT_RESUME_ONLY
    };
    return &params;
}
void parseCipher(const QString &fullCipher, QString *cipher, QString *mode, int *len)
{
    Q_ASSERT(cipher && mode);
    *cipher = fullCipher.mid(0, fullCipher.indexOf("-"));
    int idxSplit = fullCipher.indexOf("-");
    *mode = (idxSplit > 0)
            ? fullCipher.mid(idxSplit + 1)
            : "xts-plain64";
}

EncryptParams disk_encrypt_utils::bcConvertParams(const QVariantMap &params)
{
    auto toString = [&params](const QString &key) { return params.value(key).toString(); };
    return { .device = toString(encrypt_param_keys::kKeyDevice),
             .passphrase = toString(encrypt_param_keys::kKeyPassphrase),   // decode()
             .cipher = toString(encrypt_param_keys::kKeyCipher),
             .recoveryPath = toString(encrypt_param_keys::kKeyRecoveryExportPath) };
}

bool disk_encrypt_utils::bcValidateParams(const EncryptParams &params)
{
    if (!params.isValid()) {
        qWarning() << "params is not valid!";
        return false;
    }

    // check whether device exists
    struct stat blkStat;
    if (stat(params.device.toStdString().c_str(), &blkStat) != 0) {
        int errCode = errno;
        qWarning() << "query stat of device failed:"
                   << params.device
                   << strerror(errCode)
                   << errCode;
        return false;
    }
    if (!S_ISBLK(blkStat.st_mode)) {
        qWarning() << "device is not a block!"
                   << params.device
                   << blkStat.st_mode;
        return false;
    }

    // check if is valid path.
    if (!params.recoveryPath.isEmpty()
        && access(params.recoveryPath.toStdString().c_str(), F_OK) != 0) {
        qWarning() << "recovery export path is not valid!"
                   << params.recoveryPath;
        return false;
    }

    return true;
}

QString disk_encrypt_utils::bcExpRecFile(const EncryptParams &params)
{
    if (params.recoveryPath.isEmpty())
        return "";

    while (1) {
        if (!QDir(params.recoveryPath).exists()) {
            qWarning() << "the recovery key path does not exists!"
                       << params.recoveryPath;
            break;
        }
        QString recKey = bcGenRecKey();
        if (recKey.isEmpty()) {
            qWarning() << "no recovery key generated, give up export.";
            break;
        }

        QString recFileName = QString("%1/%2_recovery_key.txt")
                                      .arg(params.recoveryPath)
                                      .arg(params.device.mid(5));
        QFile recFile(recFileName);
        if (!recFile.open(QIODevice::ReadWrite)) {
            qWarning() << "cannot create recovery file!";
            break;
        }

        recFile.write(recKey.toLocal8Bit());
        recFile.flush();
        recFile.close();

        return QString(recKey);
    }

    return "";
}

QString disk_encrypt_utils::bcGenRecKey()
{
    QString recKey;
    QLibrary lib("usec-recoverykey");
    dfmbase::FinallyUtil finalClear([&] { if (lib.isLoaded()) lib.unload(); });

    if (!lib.load()) {
        qWarning() << "libusec-recoverykey load failed. use uuid as recovery key";
        return recKey;
    }

    typedef int (*FnGenKey)(char *, const size_t, const size_t);
    FnGenKey fn = (FnGenKey)(lib.resolve("usec_get_recovery_key"));
    if (!fn) {
        qWarning() << "libusec-recoverykey resolve failed. use uuid as recovery key";
        return recKey;
    }

    static const size_t kRecoveryKeySize = 24;
    char genKey[kRecoveryKeySize + 1];
    int ret = fn(genKey, kRecoveryKeySize, 1);
    if (ret != 0) {
        qWarning() << "libusec-recoverykey generate failed. use uuid as recovery key";
        return recKey;
    }

    recKey = genKey;
    return recKey;
}

EncryptError disk_encrypt_funcs::bcInitHeaderFile(const EncryptParams &params,
                                                  QString &headerPath)
{
    if (!disk_encrypt_utils::bcValidateParams(params))
        return kParamsNotValid;

    auto status = block_device_utils::bcDevStatus(params.device);
    if (status != kNotEncrypted) {
        qWarning() << "cannot encrypt device:"
                   << params.device
                   << status;
        return kDeviceEncrypted;
    }

    if (block_device_utils::bcIsMounted(params.device)) {
        qWarning() << "device is already mounted, cannot encrypt";
        return kDeviceMounted;
    }

    headerPath = bcDoSetupHeader(params);
    return headerPath.isEmpty()
            ? kUnknownError
            : kNoError;
}

QString disk_encrypt_funcs::bcDoSetupHeader(const EncryptParams &params)
{
    QString localPath = bcPrepareHeaderFile(params.device);
    if (localPath.isEmpty())
        return "";

    fs_resize::shrinkFileSystem_ext(params.device);

    struct crypt_device *cdev { nullptr };
    int ret = 0;

    dfmbase::FinallyUtil finalClear([&] {
        if (cdev) crypt_free(cdev);
        if (ret < 0) {
            ::remove(localPath.toStdString().c_str());
            fs_resize::expandFileSystem_ext(params.device);
        }
    });

    ret = crypt_init(&cdev, localPath.toStdString().c_str());
    CHECK_INT(ret, "init crypt failed " + params.device, "");

    crypt_set_rng_type(cdev, CRYPT_RNG_RANDOM);

    ret = crypt_set_data_offset(cdev, 32 * 1024);   // offset 32M
    CHECK_INT(ret, "cannot set offset " + params.device, "");

    QString cipher, mode;
    int keyLen = 256;
    parseCipher(params.cipher, &cipher, &mode, &keyLen);
    qDebug() << "encrypt with cipher:" << cipher << mode << keyLen;

    std::string cDevice = params.device.toStdString();
    struct crypt_params_luks2 luks2Params = {
        .data_alignment = 0,
        .data_device = cDevice.c_str(),
        .sector_size = 512,
        .label = nullptr,
        .subsystem = nullptr
    };
    ret = crypt_format(cdev,
                       CRYPT_LUKS2,
                       cipher.toStdString().c_str(),
                       mode.toStdString().c_str(),
                       nullptr,
                       nullptr,
                       keyLen / 8,
                       &luks2Params);
    CHECK_INT(ret, "format failed " + params.device, "");

    ret = crypt_keyslot_add_by_volume_key(cdev,
                                          CRYPT_ANY_SLOT,
                                          nullptr,
                                          0,
                                          params.passphrase.toStdString().c_str(),
                                          params.passphrase.length());
    CHECK_INT(ret, "add key failed " + params.device, "");

    QString recKey = disk_encrypt_utils::bcExpRecFile(params);
    if (!recKey.isEmpty()) {
        ret = crypt_keyslot_add_by_volume_key(cdev,
                                              CRYPT_ANY_SLOT,
                                              nullptr,
                                              0,
                                              recKey.toStdString().c_str(),
                                              recKey.length());
        if (ret < 0) {
            qWarning() << "add recovery key failed:"
                       << params.device
                       << ret;
        }
    }

    ret = crypt_reencrypt_init_by_passphrase(cdev,
                                             nullptr,
                                             params.passphrase.toStdString().c_str(),
                                             params.passphrase.length(),
                                             CRYPT_ANY_SLOT,
                                             0,
                                             cipher.toStdString().c_str(),
                                             mode.toStdString().c_str(),
                                             encryptParams());
    CHECK_INT(ret, "init reencryption failed " + params.device, "");

    // active device for expanding fs.
    QString activeDev = QString("dm-%1").arg(params.device.mid(5));
    ret = crypt_activate_by_passphrase(cdev,
                                       activeDev.toStdString().c_str(),
                                       CRYPT_ANY_SLOT,
                                       params.passphrase.toStdString().c_str(),
                                       params.passphrase.length(),
                                       CRYPT_ACTIVATE_NO_JOURNAL);
    CHECK_INT(ret, "acitve device failed " + params.device + activeDev, "");
    fs_resize::expandFileSystem_ext(QString("/dev/mapper/%1").arg(activeDev));
    ret = crypt_deactivate(nullptr, activeDev.toStdString().c_str());
    CHECK_INT(ret, "deacitvi device failed " + params.device, localPath);
    return localPath;
}

int disk_encrypt_funcs::bcInitHeaderDevice(const QString &device,
                                           const QString &passphrase,
                                           const QString &headerPath)
{
    Q_ASSERT_X(!headerPath.isEmpty() && !device.isEmpty(),
               "input params cannot be empty!", "");

    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {
        if (cdev) crypt_free(cdev);
        if (!headerPath.isEmpty()) ::remove(headerPath.toStdString().c_str());
    });

    int ret = crypt_init(&cdev, device.toStdString().c_str());
    CHECK_INT(ret, "init device failed " + device, -2);

    ret = crypt_header_restore(cdev,
                               CRYPT_LUKS2,
                               headerPath.toStdString().c_str());
    CHECK_INT(ret, "restore header failed " + device + headerPath, -3);
    return 0;
}

QString disk_encrypt_funcs::bcPrepareHeaderFile(const QString &device)
{
    QString localPath = QString("/tmp/%1_luks2_pre_enc").arg(device.mid(5));
    int fd = open(localPath.toStdString().c_str(),
                  O_CREAT | O_EXCL | O_WRONLY,
                  S_IRUSR | S_IWUSR);
    CHECK_INT(fd, "create tmp file failed " + device + strerror(errno), "");

    int ret = posix_fallocate(fd, 0, 32 * 1024 * 1024);
    close(fd);
    CHECK_BOOL(ret == 0, "allocate file failed " + localPath, "");
    return localPath;
}

int disk_encrypt_funcs::bcDecryptDevice(const QString &device,
                                        const QString &passphrase)
{
    // backup header first
    QString headerPath;
    uint32_t flags;
    struct crypt_device *cdev = nullptr;
    dfmbase::FinallyUtil finalClear([&] {
        if (cdev) crypt_free(cdev);
        if (!headerPath.isEmpty()) ::remove(headerPath.toStdString().c_str());
        gCurrDecryptintDevice.clear();
    });
    gCurrDecryptintDevice = device;

    int ret = bcBackupCryptHeader(device, headerPath);
    CHECK_INT(ret, "backup header failed " + device, ret);

    ret = crypt_init_data_device(&cdev,
                                 headerPath.toStdString().c_str(),
                                 device.toStdString().c_str());
    CHECK_INT(ret, "init device failed " + device, ret);

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    CHECK_INT(ret, "load device failed " + device, ret);

    ret = crypt_persistent_flags_get(cdev,
                                     CRYPT_FLAGS_REQUIREMENTS,
                                     &flags);
    CHECK_INT(ret, "get device flag failed " + device, ret);
    bool underEncrypting = (flags & CRYPT_REQUIREMENT_OFFLINE_REENCRYPT) || (flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT);
    CHECK_BOOL(!underEncrypting,
               "device is under encrypting... " + device + " the flags are: " + QString::number(flags),
               -1);

    ret = crypt_reencrypt_init_by_passphrase(cdev,
                                             nullptr,
                                             passphrase.toStdString().c_str(),
                                             passphrase.length(),
                                             CRYPT_ANY_SLOT,
                                             CRYPT_ANY_SLOT,
                                             nullptr,
                                             nullptr,
                                             decryptParams());
    CHECK_INT(ret, "init reencrypt failed " + device, ret);

    ret = crypt_reencrypt(cdev, bcDecryptProgress);
    CHECK_INT(ret, "decrypt failed" + device, ret);

    bool res = fs_resize::recoverySuperblock_ext(device, headerPath);
    CHECK_BOOL(res, "recovery fs failed " + device, -2);
    return 0;
}

int disk_encrypt_funcs::bcBackupCryptHeader(const QString &device, QString &headerPath)
{
    headerPath = "/tmp/dm_header_" + device.mid(5);
    struct crypt_device *cdev = nullptr;
    dfmbase::FinallyUtil finalClear([&] { if (cdev) crypt_free(cdev); });

    int ret = crypt_init(&cdev, device.toStdString().c_str());
    CHECK_INT(ret, "init device failed " + device, ret);

    ret = crypt_header_backup(cdev,
                              nullptr,
                              headerPath.toStdString().c_str());
    CHECK_INT(ret, "backup header failed " + device, ret);
    return 0;
}

int disk_encrypt_funcs::bcResumeReencrypt(const QString &device,
                                          const QString &passphrase)
{
    qDebug() << "start resume encryption for device"
             << device;
    gCurrReencryptingDevice = device;
    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {
        if (cdev) crypt_free(cdev);
        gCurrDecryptintDevice.clear();
    });

    int ret = crypt_init_data_device(&cdev,
                                     device.toStdString().c_str(),
                                     device.toStdString().c_str());
    CHECK_INT(ret, "init device failed " + device, -1);

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    CHECK_INT(ret, "load device failed " + device, -2);

    uint32_t flags;
    ret = crypt_persistent_flags_get(cdev,
                                     CRYPT_FLAGS_REQUIREMENTS,
                                     &flags);
    CHECK_INT(ret, "read flags failed " + device, -3);
    CHECK_BOOL(flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT,
               "wrong flags " + device + " flags " + QString::number(flags),
               -4);

    ret = crypt_reencrypt_init_by_passphrase(cdev,
                                             nullptr,
                                             passphrase.toStdString().c_str(),
                                             passphrase.length(),
                                             CRYPT_ANY_SLOT,
                                             CRYPT_ANY_SLOT,
                                             nullptr,
                                             nullptr,
                                             resumeParams());
    CHECK_INT(ret, "init reencrypt failed " + device, -5);

    ret = crypt_reencrypt(cdev, bcEncryptProgress);
    CHECK_INT(ret, "start resume failed " + device, -6);

    // active device for expanding fs.
    QString activeDev = QString("dm-%1").arg(device.mid(5));
    ret = crypt_activate_by_passphrase(cdev,
                                       activeDev.toStdString().c_str(),
                                       CRYPT_ANY_SLOT,
                                       passphrase.toStdString().c_str(),
                                       passphrase.length(),
                                       CRYPT_ACTIVATE_NO_JOURNAL);
    CHECK_INT(ret, "acitve device failed " + device + activeDev, -7);

    fs_resize::expandFileSystem_ext(QString("/dev/mapper/%1").arg(activeDev));

    ret = crypt_deactivate(nullptr,
                           activeDev.toStdString().c_str());
    CHECK_INT(ret, "deacitvi device failed " + device, 0);
    return 0;
}

int disk_encrypt_funcs::bcEncryptProgress(uint64_t size, uint64_t offset, void *)
{
    Q_EMIT SignalEmitter::instance()->updateEncryptProgress(gCurrReencryptingDevice,
                                                            double(offset) / size);
    return 0;
}

int disk_encrypt_funcs::bcDecryptProgress(uint64_t size, uint64_t offset, void *)
{
    Q_EMIT SignalEmitter::instance()->updateDecryptProgress(gCurrDecryptintDevice,
                                                            double(offset) / size);
    return 0;
}

int disk_encrypt_funcs::bcChangePassphrase(const QString &device, const QString &oldPassphrase, const QString &newPassphrase)
{
    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {if (cdev) crypt_free(cdev); });

    int ret = crypt_init_data_device(&cdev, device.toStdString().c_str(), nullptr);
    CHECK_INT(ret, "init device failed " + device, ret);

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    CHECK_INT(ret, "load device failed " + device, ret);

    ret = crypt_keyslot_change_by_passphrase(cdev,
                                             CRYPT_ANY_SLOT,
                                             CRYPT_ANY_SLOT,
                                             oldPassphrase.toStdString().c_str(),
                                             oldPassphrase.length(),
                                             newPassphrase.toStdString().c_str(),
                                             newPassphrase.length());
    CHECK_INT(ret, "change passphrase failed " + device, ret);
    return 0;
}

int disk_encrypt_funcs::bcChangePassphraseByRecKey(const QString &device, const QString &recoveryKey, const QString &newPassphrase)
{
    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {if (cdev) crypt_free(cdev); });

    int ret = crypt_init_data_device(&cdev,
                                     device.toStdString().c_str(),
                                     /*device.toStdString().c_str()*/ nullptr);
    CHECK_INT(ret, "init device failed " + device, ret);

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    CHECK_INT(ret, "load device failed " + device, ret);

    ret = crypt_keyslot_add_by_passphrase(cdev,
                                          CRYPT_ANY_SLOT,
                                          recoveryKey.toStdString().c_str(),
                                          recoveryKey.length(),
                                          newPassphrase.toStdString().c_str(),
                                          newPassphrase.length());
    CHECK_INT(ret, "change passphrase by rec key failed " + device, ret);
    return 0;
}

EncryptStatus block_device_utils::bcDevStatus(const QString &device)
{
    auto blkDev = block_device_utils::bcCreateBlkDev(device);
    if (!blkDev) {
        qWarning() << "cannot create block device handler:"
                   << device;
        return kStatusError;
    }

    const QString &idType = blkDev->getProperty(dfmmount::Property::kBlockIDType).toString();
    const QString &idVersion = blkDev->getProperty(dfmmount::Property::kBlockIDVersion).toString();

    if (idType == "crypto_LUKS") {
        if (idVersion == "1")
            return kLUKS1;
        if (idVersion == "2")
            return kLUKS2;
        return kUnknownLUKS;
    }

    // TODO: this should be completed, not only LUKS encrypt.

    return kNotEncrypted;
}

DevPtr block_device_utils::bcCreateBlkDev(const QString &device)
{
    auto mng = dfmmount::DDeviceManager::instance();
    Q_ASSERT_X(mng, "cannot create device manager", "");
    auto blkMonitor = mng->getRegisteredMonitor(dfmmount::DeviceType::kBlockDevice)
                              .objectCast<dfmmount::DBlockMonitor>();
    Q_ASSERT_X(blkMonitor, "cannot get valid device monitor", "");

    auto blkDevs = blkMonitor->resolveDeviceNode(device, {});
    if (blkDevs.isEmpty()) {
        qWarning() << "cannot resolve device from" << device;
        return nullptr;
    }

    auto blkDev = blkMonitor->createDeviceById(blkDevs.constFirst());
    if (!blkDev) {
        qWarning() << "cannot create device by" << blkDevs.constFirst();
        return nullptr;
    }
    return blkDev.objectCast<dfmmount::DBlockDevice>();
}

bool block_device_utils::bcIsMounted(const QString &device)
{
    auto blkDev = block_device_utils::bcCreateBlkDev(device);
    if (!blkDev) {
        qWarning() << "cannot create block device handler:"
                   << device;
        return false;
    }
    return !blkDev->mountPoints().isEmpty();
}
