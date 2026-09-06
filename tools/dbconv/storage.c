/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* storage.c - Storage services
*
*/

/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "dbconv.h"

/*********************************************************
 * Data types                                            *
 *********************************************************/
#define STF_HEADER_SIGNATURE_SIZE 6
typedef struct _StorageHeader {

    char                signature[STF_HEADER_SIGNATURE_SIZE];   /* STORAGE_SIGNATURE */
    STGVERSION          version;        /* STORAGE_CURRENT_VERSION */
    STGVERSION          data_version;
    flags_t             flags;          /* SF_* */
    time_t              last_save;

} StorageHeader;

#pragma pack(push, 4)
typedef struct _StorageHeader32 {

    char                signature[STF_HEADER_SIGNATURE_SIZE];   /* STORAGE_SIGNATURE */
    STGVERSION          version;        /* STORAGE_CURRENT_VERSION */
    STGVERSION          data_version;
    uint32_t            flags;          /* SF_* */
    int32_t             last_save;

} StorageHeader32;
#pragma pack(pop)


typedef struct _StorageDescriptor {

    FILE            *fd;
    StorageHeader   header;
    flags_t         flags;

} StorageDescriptor;


typedef struct _RecordDescriptor {

    unsigned char       signature;
    tiny_flags_t        flags; // SRF_*
    uint16_t        size;
    uint32_t        crc;

} RecordDescriptor;



/*********************************************************
 * Constants                                             *
 *********************************************************/

#define STORAGE_SIGNATURE                   "ASSTG"

#define STORAGE_CURRENT_VERSION             11
#define STORAGE_MIN_VERSION                 10
#define STORAGE_MAX_VERSION                 STORAGE_CURRENT_VERSION

#define STORAGE_COMPATIBILITY_VERSION       7

#define STORAGE_RECORD_SIGNATURE_V1         93U
#define STORAGE_CURRENT_RECORD_SIGNATURE    STORAGE_RECORD_SIGNATURE_V1

// RecordDescriptor.flags
#define RDF_TYPE_RECORD         0x01 // ------01
#define RDF_TYPE_START_SECTION  0x02 // ------10
#define RDF_TYPE_END_SECTION    0x03 // ------11
#define RDF_TYPE_MASK           0x03
#define RDF_CRC_CHECK           0x04 // -----1--


/*********************************************************
 * Global variables                                      *
 *********************************************************/

STG_RESULT  stg_last_error = stgSuccess;



/*********************************************************
 * Local variables                                       *
 *********************************************************/

#define stgVersionToSignature(v) (uint32_t)((v << 24) | ((v & 0x0000FF00) << 8) | ((v & 0x00FF0000) >> 8) | ((v & 0xFF000000) >> 24))

static uint32_t         stgCurrentVersionSignature = stgVersionToSignature(STORAGE_CURRENT_VERSION);
static uint32_t         stg32BitVersionSignature = stgVersionToSignature(STORAGE_MIN_VERSION);
static uint32_t stgCompatibilityVersionSignature = stgVersionToSignature(STORAGE_COMPATIBILITY_VERSION);

static void crc32(unsigned char *data, size_t size, uint32_t *crc);

/*********************************************************
 * Public code                                           *
 *********************************************************/


STG_RESULT stg_open(const char *path, STGHANDLE *handle) {

    STG_RESULT  result = stgBadParam;

    if (path != NULL && handle != NULL) {

        StorageDescriptor   *sd;

        *handle = STG_INVALID_HANDLE;

        sd = mowgli_alloc_array(1, sizeof(StorageDescriptor));

        sd->fd = fopen(path, "r");

        if (sd->fd != NULL) {

            uint32_t    storage_version;

            // storage version
            if (fread(&storage_version, sizeof(storage_version), 1, sd->fd) == 1) {

                if ((storage_version == stgCurrentVersionSignature)
                    || (storage_version == stg32BitVersionSignature)
                    ) {
                    if (storage_version == stgCurrentVersionSignature)
                        result = stg_read_record((STGHANDLE)sd, (unsigned char *)&(sd->header), sizeof(StorageHeader));
                    else {
                        //could be a 32bit ?
                        StorageHeader32 sd32;
                        result = stg_read_record((STGHANDLE)sd, (unsigned char *)&(sd32), sizeof(StorageHeader32));
                        sd->header.flags = sd32.flags;
                        sd->header.version = sd32.version;
                        sd->header.data_version = sd32.data_version;
                        sd->header.last_save = sd32.last_save;
                        memcpy(sd->header.signature, sd32.signature, STF_HEADER_SIGNATURE_SIZE);
                    }
                    if (result == stgSuccess) {

                        if ((sd->header.version < STORAGE_MIN_VERSION) || (sd->header.version > STORAGE_MAX_VERSION) ||
                            strncmp(sd->header.signature, STORAGE_SIGNATURE, sizeof(sd->header.signature)) != 0)
                            return stg_last_error = stgInvalidStorage;

                        else {

                            sd->flags = sd->header.flags;
                            sd->flags |= SF_READ_ACCESS;
                            *handle = (STGHANDLE)sd;
                            return stg_last_error = stgSuccess; // done
                        }
                    }
                    else
                        return stg_last_error = stgReadError;
                }
                else {

                    if (storage_version == stgCompatibilityVersionSignature) {
                        *handle = (STGHANDLE)sd;
                        return stg_last_error = stgOldStorage; // done
                    }
                    else
                        return stg_last_error = stgInvalidStorage;
                }

            }
            else
                return stg_last_error = stgReadError;
        }
        else {

            switch (errno) {

                case EACCES:
                    result = stgAccessDenied;
                    break;

                case ENOENT:
                    result = stgNotFound;
                    break;

                case EINVAL:
                case EMFILE:
                    result = stgReadError;
                    break;

                default:
                    result = stgUnknownError;
                    break;
            }
        }
    }

    return stg_last_error = result;
}

STG_RESULT stg_close(STGHANDLE handle, const char *path) {

    STG_RESULT  result = stgBadParam;

    if (handle != 0) {

        StorageDescriptor   *sd = (StorageDescriptor *)handle;

        fclose(sd->fd);
        mowgli_free(sd);

        result = stgSuccess;    // done
    }

    return stg_last_error = result;
}


STGVERSION stg_data_version(STGHANDLE handle) {
    return (handle != 0) ? ((StorageDescriptor *)handle)->header.data_version : STG_INVALID_VERSION;
}

bool stg_is64bit(STGHANDLE handle) {
    if ((handle != 0))
        return !!(((StorageDescriptor *) handle)->header.flags & SF_64BIT_RECORDS);
    return FALSE;
}

STG_RESULT stg_read_record(STGHANDLE handle, unsigned char * record, size_t record_size) {

    STG_RESULT  result = stgBadParam;

    if ((handle != 0)) {

        RecordDescriptor    rd;
        StorageDescriptor   *sd = (StorageDescriptor *)handle;
        int                 bytes_read;


        bytes_read = fread(&rd, sizeof(RecordDescriptor), 1, sd->fd);

        if (bytes_read != 1)
            return stg_last_error = feof(sd->fd) ? stgEndOfData : stgReadError; // done

        else {
            if ((bytes_read == 1) && (rd.signature == STORAGE_CURRENT_RECORD_SIGNATURE)) {


                switch (rd.flags & RDF_TYPE_MASK) {

                    case RDF_TYPE_START_SECTION:
                        return stg_last_error = stgBeginOfSection;


                    case RDF_TYPE_END_SECTION:
                        return stg_last_error = stgEndOfSection;


                    case RDF_TYPE_RECORD:

                        if (record != NULL && (record_size > 0)) {
                            if (rd.size == record_size) {

                                bytes_read = fread(record, record_size, 1, sd->fd);
                                if (bytes_read != 1)
                                    result = feof(sd->fd) ? stgEndOfData : stgReadError;    // done

                                else {

                                    if (bytes_read == 1) {

                                        if (rd.flags & RDF_CRC_CHECK) {
                                            uint32_t    crc = CRC32_INITIAL_VALUE;

                                            crc32(record, record_size, &crc);
                                            result = (crc == rd.crc) ? stgSuccess : stgCRCError;    // done
                                        } else
                                            result = stgSuccess;    // done

                                        return stg_last_error = result;

                                    } else
                                        result = stgBadFD;
                                }
                            } else
                                result = stgBadSize;
                        } else
                            result = stgBadRecord;

                        break;

                    default:
                        result = stgBadRecord;
                }
            } else
                result = stgBadRecord;
        }
    }

    return stg_last_error = result;
}

STG_RESULT stg_read_string(STGHANDLE handle, char **string, size_t *length) {

    STG_RESULT  result = stgBadParam;

    if ((handle != 0) && string != NULL) {

        RecordDescriptor    rd;
        StorageDescriptor   *sd = (StorageDescriptor *)handle;
        bool                read_done;
        char                *data;


        read_done = (fread(&rd, sizeof(RecordDescriptor), 1, sd->fd) == 1);

        if (read_done && (rd.signature == STORAGE_CURRENT_RECORD_SIGNATURE)) {

            if (length != NULL)
                *length = rd.size;

            data = mowgli_alloc(rd.size);
            read_done = (fread(data, rd.size, 1, sd->fd) == 1);

            if (read_done) {
                *string = data;

                if (sd->flags & SF_CRC_CHECK) {
                    uint32_t    crc = CRC32_INITIAL_VALUE;

                    crc32((unsigned char *)data, rd.size, &crc);
                    result = (crc == rd.crc) ? stgSuccess : stgCRCError;    // done
                } else
                    result = stgSuccess;    // done

                return stg_last_error = result;
            } else
                result = stgBadFD;
        } else
            result = stgBadRecord;
    }

    return stg_last_error = result;
}

const char *stg_result_to_string(STG_RESULT result) {

    static char buffer[36];

    switch (result) {

        case stgSuccess:
            mowgli_strlcpy(buffer, "No errors", sizeof(buffer));
            break;

        case stgBeginOfSection:
            mowgli_strlcpy(buffer, "No errors", sizeof(buffer));
            break;

        case stgEndOfSection:
            mowgli_strlcpy(buffer, "No errors", sizeof(buffer));
            break;

        case stgUnknownError:
            mowgli_strlcpy(buffer, "Unknown error", sizeof(buffer));
            break;

        case stgBadParam:
            mowgli_strlcpy(buffer, "Bad parameter(s)", sizeof(buffer));
            break;

        case stgNotFound:
            mowgli_strlcpy(buffer, "Path not found", sizeof(buffer));
            break;

        case stgBadFD:
            mowgli_strlcpy(buffer, "Bad file descriptor", sizeof(buffer));
            break;

        case stgOutOfSpace:
            mowgli_strlcpy(buffer, "Out of disk space", sizeof(buffer));
            break;

        case stgAccessDenied:
            mowgli_strlcpy(buffer, "Access denied", sizeof(buffer));
            break;

        case stgReadOnly:
            mowgli_strlcpy(buffer, "Read-only storage", sizeof(buffer));
            break;

        case stgWriteOnly:
            mowgli_strlcpy(buffer, "Write-only storage", sizeof(buffer));
            break;

        case stgReadError:
            mowgli_strlcpy(buffer, "Read error", sizeof(buffer));
            break;

        case stgWriteError:
            mowgli_strlcpy(buffer, "Write error", sizeof(buffer));
            break;

        case stgInvalidStorage:
            mowgli_strlcpy(buffer, "Invalid storage", sizeof(buffer));
            break;

        case stgBadSize:
            mowgli_strlcpy(buffer, "Record size mismatch", sizeof(buffer));
            break;

        case stgBadRecord:
            mowgli_strlcpy(buffer, "Invalid record", sizeof(buffer));
            break;

        case stgOldStorage:
            mowgli_strlcpy(buffer, "Old storage format", sizeof(buffer));
            break;

        case stgCantBackup:
            mowgli_strlcpy(buffer, "Unable to backup previous storage", sizeof(buffer));
            break;

        case stgCantRestore:
            mowgli_strlcpy(buffer, "Unable to restore previous storage", sizeof(buffer));
            break;

        case stgCRCError:
            mowgli_strlcpy(buffer, "CRC error on data", sizeof(buffer));
            break;

        case stgEndOfData:
            mowgli_strlcpy(buffer, "No more data on the storage", sizeof(buffer));
            break;

        default:
            mowgli_strlcpy(buffer, "Unknow status value", sizeof(buffer));
            break;
    }

    return (const char *) buffer;
}

/*********************************************************
 * CRC                                                   *
 *********************************************************/

// Static CRC table
static uint32_t crc32_table[256] = {

    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};


static void compute_crc32(const unsigned char byte, uint32_t *crc) {
    *crc = ((*crc) >> 8) ^ crc32_table[(byte) ^ ((*crc) & 0x000000FF)];
}

static void crc32(unsigned char *data, size_t size, uint32_t *crc) {
    size_t idx;

    for(idx = 0; idx < size; ++idx)
        compute_crc32(data[idx], crc);

        *crc = ~(*crc);
}
