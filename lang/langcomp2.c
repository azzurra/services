#include <stdio.h>
#include <glob.h>
#include <stdint.h>
#include <time.h>

typedef		char *			STR;
typedef unsigned int		LANG_VERSION;
typedef unsigned int		LANG_ID;
typedef LANG_ID				LANG_MSG_ID;
typedef STR					LANG_MSG;
typedef unsigned short int	LANG_MSG_SIZE;
typedef LANG_MSG *			LANG_TABLE;

typedef struct lang_item32 {

    unsigned int		flags;
    uint32_t			time_loaded;
    uint32_t			time_created;
    uint32_t			lang_name_loc; /* nome della lingua */
    uint32_t			lang_name_eng; /* nome della lingua in inglese */
    char				lang_short_name[3]; /* sigla della lingua (eg: IT, US, FR) */
    uint64_t			memory_size;
    LANG_TABLE			msgs;
    char				news_path[30];
    uint32_t				news_size;
} LANG_ITEM32;

typedef struct lang_item64 {

    unsigned int		flags;
    time_t	    		time_loaded;
    time_t  			time_created;
    STR					lang_name_loc; /* nome della lingua */
    STR					lang_name_eng; /* nome della lingua in inglese */
    char				lang_short_name[3]; /* sigla della lingua (eg: IT, US, FR) */
    uint64_t	        memory_size;
    LANG_TABLE			msgs;
    char				news_path[30];
    size_t				news_size;
} LANG_ITEM64;

typedef struct lang_file_header32 {

    LANG_VERSION		version;
    LANG_ID				lang_id;
    uint32_t				created;
    unsigned int		standard_flags;
    unsigned int		message_count;
    char				lang_short_name[3];
    LANG_MSG_SIZE		name_loc_size;
    LANG_MSG_SIZE		name_eng_size;
    uint32_t	signature;

} LANG_FILE_HEADER32;

typedef struct lang_file_header64 {

    LANG_VERSION		version;
    LANG_ID				lang_id;
    uint64_t				created;
    unsigned int		standard_flags;
    unsigned int		message_count;
    char				lang_short_name[3];
    LANG_MSG_SIZE		name_loc_size;
    LANG_MSG_SIZE		name_eng_size;
    unsigned long int	signature;

} LANG_FILE_HEADER64;

typedef struct lang_file_msg_header {

    LANG_MSG_ID		id;
    LANG_MSG_SIZE	size;

} LANG_FILE_MSG_HEADER;

int convert(STR filename) {
    int ret = 0;
    LANG_FILE_HEADER32 header32;
    LANG_FILE_HEADER64 header64;
    FILE *f64 = fopen(filename, "wb");
    ftruncate(fileno(f64), 0);

    FILE *f = fopen(filename, "rb");
    if (f == NULL || f64 == NULL) {
        fprintf(stderr, "Error opening file\n");
        ret = 1;
        goto exit;
    }
    fread(&header32, sizeof(header32), 1, f);
    printf("Lang: %s, signature: %x, version: %d\r\n", header32.lang_short_name, header32.signature, header32.version);

    /*LANG_VERSION		version;
    LANG_ID				lang_id;
    uint64_t				created;
    unsigned int		standard_flags;
    unsigned int		message_count;
    char				lang_short_name[3];
    LANG_MSG_SIZE		name_loc_size;
    LANG_MSG_SIZE		name_eng_size;
    unsigned long int	signature;
*/
    header64.version = header32.version;
    header64.lang_id = header32.lang_id;
    header64.created = header32.created;
    header64.standard_flags = header32.standard_flags;
    header64.message_count = header32.message_count;
    header64.lang_short_name[0] = header32.lang_short_name[0];
    header64.lang_short_name[1] = header32.lang_short_name[1];
    header64.lang_short_name[2] = header32.lang_short_name[2];
    header64.name_loc_size = header32.name_loc_size;
    header64.name_eng_size = header32.name_eng_size;
    header64.signature = header32.signature;
    fwrite(&header64, sizeof(header64), 1, f64);
    //then we have 2 strings of length loc_size and eng_size
    char loc_str[header64.name_loc_size];
    char eng_str[header64.name_eng_size];
    fread(loc_str, header64.name_loc_size, 1, f);
    fread(eng_str, header64.name_eng_size, 1, f);
    fwrite(loc_str, header64.name_loc_size, 1, f64);
    fwrite(eng_str, header64.name_eng_size, 1, f64);

    for (int i=0; i<header64.message_count; i++) {
        //then we have a message header
        LANG_FILE_MSG_HEADER msgheader32;
    }


exit:
    fclose(f);
    fclose(f64);
    return ret;
}

int main() {
    glob_t results;
    glob("*.clng", 0, NULL, &results);

    for (size_t i = 0; i < results.gl_pathc; i++) {
        printf("%s...", results.gl_pathv[i]);
        if (convert(results.gl_pathv[i]) == 0)
            printf("[OK]\r\n");
        else
            printf("[ERROR]\r\n");
    }
    return 0;
}

