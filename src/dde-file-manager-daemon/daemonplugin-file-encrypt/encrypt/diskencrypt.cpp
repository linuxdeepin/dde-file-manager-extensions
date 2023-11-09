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
#include <QUuid>

#include <dfm-base/utils/finallyutil.h>
#include <dfm-mount/dmount.h>

#include <libcryptsetup.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <functional>

FILE_ENCRYPT_USE_NS

static constexpr char kResumeList[] { "/etc/resume_encrypt_list.txt" };
// used to record current reencrypting device.
QString gCurrReencryptingDevice;
QString gCurrDecryptintDevice;

EncryptParams disk_encrypt_utils::bcConvertEncParams(const QVariantMap &params)
{
    // TODO(xust): the passphrase should be a cypher.
    // use openssl to provide a public key for encode the passphrase
    // and the private key to decode passphrase

    auto toString = [&params](const QString &key) {
        return params.value(key).toString();
    };
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

void disk_encrypt_utils::bcCachePendingEncryptInfo(const QString &device,
                                                   const QString &passphrase)
{
    // TODO passphrase cannot be recored as cleartext.
    QFile f(kResumeList);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Append)) {
        qWarning() << "cannot open resume list";
        return;
    }

    QTextStream s(&f);
    s << device << " " << passphrase << "\n";
    s.flush();
    f.close();
}

QStringList disk_encrypt_utils::bcResumeDeviceList()
{
    QFile f(kResumeList);
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "cannot open resume list for read!";
        return {};
    }
    QByteArray data = f.readAll();
    f.close();

    QStringList resumeList = QString(data).split("\n", QString::SkipEmptyParts);
    return resumeList;
}

void disk_encrypt_utils::bcClearCachedPendingList()
{
    QFile f(kResumeList);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "cannot open resume list";
        return;
    }
    f.close();
}

QString disk_encrypt_utils::bcExportRecoveryFile(const EncryptParams &params)
{
    if (!params.recoveryPath.isEmpty()) {
        while (1) {
            if (!QDir(params.recoveryPath).exists()) {
                qWarning() << "the recovery key path does not exists!"
                           << params.recoveryPath;
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

            QString recKey = bcGenerateRecoveryKey();
            recFile.write(recKey.toLocal8Bit());
            recFile.flush();
            recFile.close();

            return QString(recKey);
        }
    }
    return "";
}

QString disk_encrypt_utils::bcGenerateRecoveryKey()
{
    QLibrary lib("usec-recoverykey");
    dfmbase::FinallyUtil finalClear([&] { if (lib.isLoaded()) lib.unload(); });

    QString recKey = QUuid::createUuid().toString();
    if (!lib.load()) {
        qWarning() << "libusec-recoverykey load failed. use uuid as recovery key";
        return recKey;
    }

    typedef int (*FnGenKey)(char *, const size_t, const size_t);
    FnGenKey fn = (FnGenKey)(lib.resolve("usec_get_recovery_key"));
    if (!fn) {
        qWarning() << "libusec-recoverykey resolve failed. use uuid as recovery key";
        return recKey;
    } else {
        static const size_t kRecoveryKeySize = 20;
        char genKey[kRecoveryKeySize + 1];
        int ret = fn(genKey, kRecoveryKeySize, 1);
        if (ret != 0) {
            qWarning() << "libusec-recoverykey generate failed. use uuid as recovery key";
            return recKey;
        }
        recKey = genKey;
        return recKey;
    }
}

EncryptError disk_encrypt_funcs::bcInitHeaderFile(const EncryptParams &params,
                                                  QString &headerPath)
{
    if (!disk_encrypt_utils::bcValidateParams(params))
        return kParamsNotValid;

    // check if device is already encrypted
    auto status = block_device_utils::bcQueryDeviceEncryptStatus(params.device);
    if (status != kNotEncrypted) {
        qWarning() << "cannot encrypt device:"
                   << params.device
                   << status;
        return kDeviceEncrypted;
    }

    // check if device is already mounted.
    if (block_device_utils::bcIsAlreadyMounted(params.device)) {
        qWarning() << "device is already mounted, cannot encrypt";
        return kDeviceMounted;
    }

    // DON'T encrypt those devices which is configured in /etc/fstab.
    // daemon cannot do encrypt resume before it mounted.

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

    ret = crypt_init(&cdev,
                     localPath.toStdString().c_str());
    if (ret != 0) {
        qWarning() << "cannot init crypt device:"
                   << ret
                   << params.device;
        return "";
    }

    crypt_set_rng_type(cdev, CRYPT_RNG_RANDOM);

    ret = crypt_set_data_offset(cdev, 32 * 1024);   // offset 32M
    if (ret != 0) {
        qWarning() << "cannot set offset 32M:"
                   << ret
                   << params.device;
    }

    // seems that PBKDF is not necessary, complete it later.

    std::string cDevice = params.device.toStdString();

    // set pkbdf
    /*
    const auto *dftPbkdf = crypt_get_pbkdf_default(CRYPT_LUKS2);
    struct crypt_pbkdf_type pbkdf = {
        .type = "argon2id",
        .hash = "sm3",
        .time_ms = dftPbkdf->time_ms,
        .max_memory_kb = dftPbkdf->max_memory_kb,
        .parallel_threads = dftPbkdf->parallel_threads
    };
    ret = crypt_set_pbkdf_type(cdev, &pbkdf);
    if (ret != 0) {
        qWarning() << "cannot set PBKDF for device"
                   << params.device
                   << ret;
        return "";
    }
*/

    struct crypt_params_luks2 luks2Params = {
        .data_alignment = 0,
        .data_device = cDevice.c_str(),
        .sector_size = 512,
        .label = nullptr,
        .subsystem = nullptr
    };
    QString cipher = params.cipher.mid(0, params.cipher.indexOf("-"));
    int idxSplit = params.cipher.indexOf("-");
    QString mode = (idxSplit > 0)
            ? params.cipher.mid(idxSplit + 1)
            : "xts-plain64";

    qDebug() << "encrypt cipher is"
             << cipher
             << "and cipher mode is"
             << mode;

    ret = crypt_format(cdev,
                       CRYPT_LUKS2,
                       cipher.toStdString().c_str(),
                       mode.toStdString().c_str(),
                       nullptr,
                       nullptr,
                       256 / 8,
                       &luks2Params);
    if (ret < 0) {
        qWarning() << "luks format failed for device:"
                   << params.device
                   << ret;
        return "";
    }

    // add key slots
    std::string cPassphrase = params.passphrase.toStdString();
    ret = crypt_keyslot_add_by_volume_key(cdev,
                                          CRYPT_ANY_SLOT,
                                          nullptr,
                                          0,
                                          cPassphrase.c_str(),
                                          params.passphrase.length());
    if (ret < 0) {
        qWarning() << "add key slot failed:"
                   << params.device
                   << ret;
        return "";
    }

    QString recKey = disk_encrypt_utils::bcExportRecoveryFile(params);
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

    // Initialize reencryption metadata using passphrase.
    struct crypt_params_luks2 reencLuks2
    {
        .sector_size = 512
    };

    struct crypt_params_reencrypt reencParams
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

    ret = crypt_reencrypt_init_by_passphrase(cdev,
                                             nullptr,
                                             cPassphrase.c_str(),
                                             strlen(cPassphrase.c_str()),
                                             CRYPT_ANY_SLOT,
                                             0,
                                             cipher.toStdString().c_str(),
                                             mode.toStdString().c_str(),
                                             &reencParams);
    if (ret < 0) {
        qWarning() << "failed to init reencrypt!"
                   << params.device
                   << ret;
        return "";
    }

    return localPath;
}

int disk_encrypt_funcs::bcInitHeaderDevice(const QString &device,
                                           const QString &passphrase,
                                           const QString &headerPath)
{
    if (headerPath.isEmpty() || device.isEmpty()) {
        qWarning() << "device or header file path is empty"
                   << device
                   << headerPath;
        return -1;
    }

    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {if (cdev) crypt_free(cdev); });

    int ret = crypt_init(&cdev,
                         device.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot init crypt device for device"
                   << device
                   << ret;
        return -2;
    }

    ret = crypt_header_restore(cdev,
                               CRYPT_LUKS2,
                               headerPath.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot restore header from file"
                   << headerPath
                   << "for device"
                   << device
                   << ret;
        return -3;
    }

    ::remove(headerPath.toStdString().c_str());

    // once restore from header file success
    // record to local file and guide user reboot device
    // to continue reencrypt.
    disk_encrypt_utils::bcCachePendingEncryptInfo(device,
                                                  passphrase);

    return 0;
}

QString disk_encrypt_funcs::bcPrepareHeaderFile(const QString &device)
{
    QString localPath = QString("/tmp/%1_luks2_pre_enc").arg(device.mid(5));
    int fd = open(localPath.toStdString().c_str(),
                  O_CREAT | O_EXCL | O_WRONLY,
                  S_IRUSR | S_IWUSR);
    if (fd == -1) {
        qWarning() << "cannot create temp encrypt header:"
                   << strerror(errno)
                   << device;
        return "";
    }

    int ret = posix_fallocate(fd, 0, 32 * 1024 * 1024);
    close(fd);
    if (ret != 0) {
        qWarning() << "failed to allocate space for file:"
                   << localPath
                   << ret
                   << device;
        return "";
    }
    return localPath;
}

int disk_encrypt_funcs::bcDecryptDevice(const QString &device,
                                        const QString &passphrase)
{
    // backup header first
    QString headerPath;
    int ret = bcBackupCryptHeader(device, headerPath);
    if (ret < 0) {
        qWarning() << "cannot backup device header"
                   << device
                   << ret;
        return ret;
    }

    struct crypt_device *cdev = nullptr;
    ret = crypt_init_data_device(&cdev,
                                 headerPath.toStdString().c_str(),
                                 device.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot init deivce"
                   << device
                   << ret;
        return ret;
    }

    dfmbase::FinallyUtil finalClear([&] {
        if (cdev) crypt_free(cdev);
        ::remove(headerPath.toStdString().c_str());
    });

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    if (ret < 0) {
        qWarning() << "cannot load crypt device!"
                   << device
                   << ret;
        return ret;
    }

    uint32_t flags;
    ret = crypt_persistent_flags_get(cdev,
                                     CRYPT_FLAGS_REQUIREMENTS,
                                     &flags);
    if (ret < 0) {
        qWarning() << "cannot get requirements flag"
                   << device
                   << ret;
        return ret;
    }

    if (flags & (CRYPT_REQUIREMENT_OFFLINE_REENCRYPT | CRYPT_REQUIREMENT_OFFLINE_REENCRYPT)) {
        qWarning() << "device need to be encrypt, cannot decrypt"
                   << device
                   << flags;
        return -1;
    }

    struct crypt_params_reencrypt params
    {
        .mode = CRYPT_REENCRYPT_DECRYPT,
        .direction = CRYPT_REENCRYPT_BACKWARD,
        .resilience = "checksum",
        .hash = "sha256",
        .data_shift = 0,
        .max_hotzone_size = 0,
        .device_size = 0
    };

    ret = crypt_reencrypt_init_by_passphrase(cdev,
                                             nullptr,
                                             passphrase.toStdString().c_str(),
                                             passphrase.length(),
                                             CRYPT_ANY_SLOT,
                                             CRYPT_ANY_SLOT,
                                             nullptr,
                                             nullptr,
                                             &params);
    if (ret < 0) {
        qWarning() << "cannot init reencrypt!"
                   << device
                   << ret;
        return ret;
    }

    gCurrDecryptintDevice = device;
    ret = crypt_reencrypt(cdev, bcDecryptProgress);
    gCurrDecryptintDevice.clear();
    if (ret < 0) {
        qWarning() << "decrypt device failed!"
                   << device
                   << ret;
        return ret;
    }

    bool res = fs_resize::recoverySuperblock_ext(device,
                                                 headerPath);
    if (!res) {
        qWarning() << "cannot recovery fs superblock!"
                   << device;
        return -2;
    }
    return 0;
}

int disk_encrypt_funcs::bcBackupCryptHeader(const QString &device, QString &headerPath)
{
    headerPath = "/tmp/dm_header_" + device.mid(5);
    struct crypt_device *cdev = nullptr;
    dfmbase::FinallyUtil finalClear([&] { if (cdev) crypt_free(cdev); });

    int ret = crypt_init(&cdev,
                         device.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot init crypt struct!"
                   << device
                   << ret;
        return ret;
    }

    ret = crypt_header_backup(cdev,
                              nullptr,
                              headerPath.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot backup device header!"
                   << device
                   << ret;
        return ret;
    }

    return 0;
}

int disk_encrypt_funcs::bcResumeReencrypt(const QString &device,
                                          const QString &passphrase)
{
    qDebug() << "start resume encryption for device"
             << device;

    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {
        if (cdev) crypt_free(cdev);
    });

    int ret = crypt_init_data_device(&cdev,
                                     device.toStdString().c_str(),
                                     device.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot init crypt device!"
                   << device
                   << ret;
        return -1;
    }

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    if (ret < 0) {
        qWarning() << "cannot load crypt device"
                   << device
                   << ret;
        return -2;
    }

    // obtain the flags of reencrypt
    uint32_t flags;
    ret = crypt_persistent_flags_get(cdev,
                                     CRYPT_FLAGS_REQUIREMENTS,
                                     &flags);
    if (ret < 0) {
        qWarning() << "cannot read crypt requirements for device"
                   << device
                   << ret;
        return -3;
    }

    if (!(flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT)) {
        qWarning() << "crypt flag not correct." << flags;
        return -4;
    }

    struct crypt_params_reencrypt params
    {
        .mode = CRYPT_REENCRYPT_REENCRYPT,
        .direction = CRYPT_REENCRYPT_FORWARD,
        .resilience = "checksum",
        .hash = "sha256",
        .max_hotzone_size = 0,
        .device_size = 0,
        .flags = CRYPT_REENCRYPT_RESUME_ONLY
    };
    std::string cPass = passphrase.toStdString();
    ret = crypt_reencrypt_init_by_passphrase(cdev,
                                             nullptr,
                                             cPass.c_str(),
                                             passphrase.length(),
                                             CRYPT_ANY_SLOT,
                                             CRYPT_ANY_SLOT,
                                             nullptr,
                                             nullptr,
                                             &params);
    if (ret < 0) {
        qWarning() << "cannot init reencrypt in resume mode"
                   << device
                   << ret;
        return -5;
    }

    gCurrReencryptingDevice = device;
    ret = crypt_reencrypt(cdev,
                          bcEncryptProgress);
    if (ret < 0) {
        qWarning() << "cannot start resume reencrypt"
                   << device
                   << ret;
        gCurrReencryptingDevice.clear();
        return -6;
    }
    qInfo() << "encrypt finished" << gCurrReencryptingDevice;
    gCurrReencryptingDevice.clear();

    // active device for expanding fs.
    QString activeDev = QString("dm-%1").arg(device.mid(5));
    ret = crypt_activate_by_passphrase(cdev,
                                       activeDev.toStdString().c_str(),
                                       CRYPT_ANY_SLOT,
                                       cPass.c_str(),
                                       passphrase.length(),
                                       CRYPT_ACTIVATE_NO_JOURNAL);
    if (ret < 0) {
        qWarning() << "cannot active device"
                   << device
                   << activeDev
                   << ret;
        return -7;
    }

    fs_resize::expandFileSystem_ext(QString("/dev/mapper/%1").arg(activeDev));

    ret = crypt_deactivate(nullptr,
                           activeDev.toStdString().c_str());
    if (ret < 0) {
        qWarning() << "cannot deactive device."
                   << device
                   << ret;
    }

    return 0;
}

int disk_encrypt_funcs::bcEncryptProgress(uint64_t size, uint64_t offset, void *)
{
    //    qInfo() << "encrypting..."
    //            << size
    //            << offset
    //            << double(offset) / size
    //            << gCurrReencryptingDevice;
    SignalEmitter::instance()->updateEncryptProgress(gCurrReencryptingDevice,
                                                     double(offset) / size);
    return 0;
}

int disk_encrypt_funcs::bcDecryptProgress(uint64_t size, uint64_t offset, void *)
{
    //    qInfo() << "decrypting device..." << gCurrDecryptintDevice
    //            << size
    //            << offset
    //            << double(offset) / size;
    SignalEmitter::instance()->updateDecryptProgress(gCurrDecryptintDevice,
                                                     double(offset) / size);
    return 0;
}

int disk_encrypt_funcs::bcChangePassphrase(const QString &device, const QString &oldPassphrase, const QString &newPassphrase)
{
    struct crypt_device *cdev { nullptr };
    dfmbase::FinallyUtil finalClear([&] {if (cdev) crypt_free(cdev); });

    int ret = crypt_init_data_device(&cdev,
                                     device.toStdString().c_str(),
                                     /*device.toStdString().c_str()*/ nullptr);
    if (ret < 0) {
        qWarning() << "cannot init crypt device!"
                   << device
                   << ret;
    }

    ret = crypt_load(cdev, CRYPT_LUKS, nullptr);
    if (ret < 0) {
        qWarning() << "cannot load crypt device!"
                   << device
                   << ret;
        return ret;
    }

    ret = crypt_keyslot_change_by_passphrase(cdev,
                                             CRYPT_ANY_SLOT,
                                             CRYPT_ANY_SLOT,
                                             oldPassphrase.toStdString().c_str(),
                                             oldPassphrase.length(),
                                             newPassphrase.toStdString().c_str(),
                                             newPassphrase.length());
    if (ret < 0) {
        qWarning() << "cannot add passphrase by old passphrase!"
                   << device
                   << ret;
        return ret;
    }

    return 0;
}

EncryptStatus block_device_utils::bcQueryDeviceEncryptStatus(const QString &device)
{
    auto blkDev = block_device_utils::bcCreateBlockDevicePtr(device);
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

QSharedPointer<dfmmount::DBlockDevice> block_device_utils::bcCreateBlockDevicePtr(const QString &device)
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

bool block_device_utils::bcIsAlreadyMounted(const QString &device)
{
    auto blkDev = block_device_utils::bcCreateBlockDevicePtr(device);
    if (!blkDev) {
        qWarning() << "cannot create block device handler:"
                   << device;
        return false;
    }
    return !blkDev->mountPoints().isEmpty();
}
