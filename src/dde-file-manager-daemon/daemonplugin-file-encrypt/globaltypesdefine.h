#ifndef GLOBALTYPESDEFINE_H
#define GLOBALTYPESDEFINE_H

enum EncryptOperationStatus {
    kSuccess = 0,
    kUserCancelled,
    kRebootRequired,

    kErrorParamsInvalid,
    kErrorDeviceMounted,
    kErrorDeviceEncrypted,
    kErrorWrongPassphrase,
    kErrorEncryptBusy,
    kErrorCannotStartEncryptJob,
    kErrorCreateHeader,
    kErrorBackupHeader,
    kErrorApplyHeader,
    kErrorInitCrypt,
    kErrorInitReencrypt,
    kErrorRestoreFromFile,
    kErrorActive,
    kErrorDeactive,
    kErrorLoadCrypt,
    kErrorGetReencryptFlag,
    kErrorWrongFlags,
    kErrorSetOffset,
    kErrorFormatLuks,
    kErrorAddKeyslot,
    kErrorReencryptFailed,
    kErrorDecryptFailed,
    kErrorOpenFstabFailed,
    kErrorChangePassphraseFailed,
    kErrorOpenFileFailed,
    kErrorSetTokenFailed,
    kErrorResizeFs,

    kErrorUnknown,
};

#endif // GLOBALTYPESDEFINE_H
