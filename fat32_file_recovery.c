#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <openssl/sha.h>


#define PRINTFILESYS 'i'
#define PRINTROOT 'l'
#define RECOVERCONTIGUOUS 'r'
#define RECOVERNONCONTIGUOUS 'R'
#define SHA_DIGEST_LENGTH 20

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)


void print_file_sys_info(BootEntry *bt);
void print_root_dir(char *addr);
char* get_name(unsigned char *st, int dir);
int get_cluster(short low, short high);
void print_usage();
int get_cluster_address(int clstr);
void recover_file(char *recovery_file_name, char *addr, bool flags, char *sha);
void correct_fat_chain(int start_clstr, int file_size);
int count_match(char *recovery_file_name, char *addr);
void read_file_into_memory(unsigned int start_cluster, unsigned char *buffer, size_t file_size, const char *addr);


unsigned int root_cluster;
unsigned int first_data_sector;
unsigned int first_root_dir_sector;
unsigned int root_dir_address;
int entry_list_size = 0;
unsigned int *fat1;
int *fat2;

BootEntry *bt;

int main(int argc, char *argv[]) {
    int opt='1';
    
    char *sha = malloc(sizeof(char)*180);
    char *file_name = malloc(sizeof(char)*11);
    char *recovery_file_name = malloc(sizeof(char)*11);
    extern char *optarg;
    extern int optind;
    
    if(argc == 1) {
        print_usage();
        return 0;
    }

    char opt_f='1';
    bool flagi = false;
    bool flagl= false;
    bool flagr= false;
    bool flagR= false;
    bool flags= false;
    opterr = 0;
    extern int optopt;
    
    while((opt = getopt(argc, argv, "ilr:R:s:"))!= -1) {
        switch (opt)
        {
        case 'i':
            flagi = true;
            opt_f = 'i'; 
            break;
        case 'l':
            flagl = true;
            opt_f = 'l';
            break;
        case 'r':
            flagr = true;
            opt_f = 'r';
            recovery_file_name = optarg;
            if(*file_name =='-') {
                print_usage();
                return 0;
            }
            break;
        case 'R':
            flagR = true;
            opt_f = 'R';
            recovery_file_name = optarg;
            if(*file_name =='-') {
                print_usage();
                return 0;
            }
            break;
        case 's':
            sha = optarg;
            flags = true;
            break;
        case '?':
            print_usage();
            return 0;
            break;    
        default:
            break;
        }
    }
    if((!flagi && !flagl && !flagr && !flagR && !flags)) {
        print_usage();
        return 0;
    }
    if(flagi && flagl) {
        print_usage();
        return 0;
    }
    if((flagi && (flagr || flagR)) || ((flagr || flagR) && flagl)) {
        print_usage();
        return 0;
    }
    if(flagr && flagR) {
        print_usage();
        return 0;
    }
    if((flagi || flagl) && flags) {
        print_usage();
        return 0;
    }
    if(sha) {

    }
    
    if(argv[optind] == NULL) {
        print_usage();
        return 0;
    }
    else {
        file_name = argv[optind];
    }
        
    
    int fd = open(file_name, O_RDWR);
    if(fd == -1) {
        print_usage();
        return 0;
    }
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        fprintf(stderr, "Error");
    }  
    char *addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    bt = (BootEntry *)(addr);

    root_cluster = bt->BPB_RootClus;
    first_data_sector = bt->BPB_RsvdSecCnt+(bt->BPB_NumFATs * bt->BPB_FATSz32);
    first_root_dir_sector = first_data_sector + (root_cluster - 2) * bt->BPB_SecPerClus;
    root_dir_address = first_root_dir_sector*bt->BPB_BytsPerSec;
    fat1 = (unsigned int*)(addr + bt->BPB_RsvdSecCnt*bt->BPB_BytsPerSec);
    fat2 = (int *)(addr+(bt->BPB_RsvdSecCnt+(bt->BPB_NumFATs-1) * bt->BPB_FATSz32)*bt->BPB_BytsPerSec);
    switch (opt_f)
    {
    case 'i':
        print_file_sys_info(bt);
        break;
    case 'l':
        print_root_dir(addr);
        break;
    case 'r':
        recover_file(recovery_file_name, addr, flags, sha);
        break;
    default:
        break;
    }
    munmap(addr, sb.st_size);
    return 0;


}

void print_file_sys_info(BootEntry *bt) {
    printf("Number of FATs = %d\n", bt->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", bt->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", bt->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", bt->BPB_RsvdSecCnt);
}

void print_root_dir(char *addr) {
    
    int temp_root_clstr = root_cluster;
    int c=0;
    
    DirEntry *dt;
    while( temp_root_clstr < 0x0ffffff8 ) {
        dt = (DirEntry *)(addr+get_cluster_address(temp_root_clstr));
        int total_entries = (bt->BPB_SecPerClus*bt->BPB_BytsPerSec)/32;
    while(dt->DIR_Name[0] != 0x00 && total_entries>0) {
        if(dt->DIR_Name[0] == '.') {
            dt++;
            continue;
        }
        if(dt->DIR_Name[0] != 0xE5 && dt->DIR_Attr != 0x0f && dt->DIR_Attr != 0x00) {
            c++;
            if(dt->DIR_Attr & 0x10) {
                char *name = get_name(dt->DIR_Name,1);
                int clstr = get_cluster(dt->DIR_FstClusLO, dt->DIR_FstClusHI);
                printf("%s (starting cluster = %d)\n", name, clstr);
            }
            else {
                char *name = get_name(dt->DIR_Name,0);
                if(dt->DIR_FileSize != 0) {
                    int clstr = get_cluster(dt->DIR_FstClusLO, dt->DIR_FstClusHI);
                    printf("%s (size = %d, starting cluster = %d)\n", name,dt->DIR_FileSize, clstr);
                }
                else {
                    printf("%s (size = 0)\n", name);
                }
                
            }
        }
        dt++;
        total_entries--;
    }
        temp_root_clstr = fat1[temp_root_clstr];
    }
    printf("Total number of entries = %d\n",c);
}

char* get_name(unsigned char *st, int dir) {
    bool has_ex = false;
    char *name = malloc(sizeof(char)*13);
    int j=0;
    for(int i=0;i<8;i++) {
        
        if(*(st+i)!= ' ') {
            *(name+j) = *(st+i);
            j++;
        }
        

    }
    for(int i=8;i<=10;i++) {
        if(*(st+i)!= ' ') {
            has_ex = true;
            break;
        }
    }
    if(has_ex && dir == 0) {
            *(name+j) = '.';
            j++;       
    }
    if(has_ex) {
        for(int i=8;i<=10;i++) {
            if(*(st+i)!= ' ') {
                *(name+j) = *(st+i);
                j++;
            }
        }
    }


    if(dir) {
        *(name+j) = '/';
        j++;
    }
    *(name+j) = '\0';
    return name;
}

int get_cluster(short low, short high) {
    int clstr = ((int)high << 16) | low;
    return clstr;
}

void print_usage() {
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

int get_cluster_address(int clstr) {
    int fds = bt->BPB_RsvdSecCnt+(bt->BPB_NumFATs * bt->BPB_FATSz32);
    int frds = fds + (clstr - 2) * bt->BPB_SecPerClus;
    int rda = frds*bt->BPB_BytsPerSec;
    return rda;
}

void recover_file(char *recovery_file_name, char *addr, bool flags, char *sha) {
    
    unsigned int temp_root_clstr = root_cluster;
    int matches = count_match(recovery_file_name, addr);
    if(matches>1 && !flags) {
        printf("%s: multiple candidates found\n",recovery_file_name);
        return;
    }
    else if(matches == 1 && !flags){
        while(temp_root_clstr < 0x0ffffff8 ) {
            int total_entries = (bt->BPB_SecPerClus*bt->BPB_BytsPerSec)/32;
            DirEntry *dt = (DirEntry *)(addr+get_cluster_address(temp_root_clstr));
            while(dt->DIR_Name[0] != 0x00 && total_entries>0) {   
            
                if(dt->DIR_Name[0] == 0xE5) {
                    if(strcmp((get_name(dt->DIR_Name,0)+1),(recovery_file_name+1))==0) {
                        int start_cluster = get_cluster(dt->DIR_FstClusLO, dt->DIR_FstClusHI);
                        correct_fat_chain(start_cluster, dt->DIR_FileSize);
                        dt->DIR_Name[0] = *recovery_file_name;
                        printf("%s: successfully recovered\n", recovery_file_name);
                        return;            
                    }
                    
                }
                dt++;
                total_entries--;
            }
        temp_root_clstr = fat1[temp_root_clstr];
        }
    }
    else if(matches == 0) {
        printf("%s: file not found\n", recovery_file_name);
    }
    else{
        while(temp_root_clstr < 0x0ffffff8 ) {
        
            int total_entries = (bt->BPB_SecPerClus*bt->BPB_BytsPerSec)/32;
            DirEntry *dt = (DirEntry *)(addr+get_cluster_address(temp_root_clstr));
            while(dt->DIR_Name[0] != 0x00 && total_entries>0) {
            //char *t = (get_name(dt->DIR_Name,0)+1);
            
            if(dt->DIR_Name[0] == 0xE5) {
                if(strcmp((get_name(dt->DIR_Name,0)+1),(recovery_file_name+1))==0) {
                    unsigned char *file_data = malloc(dt->DIR_FileSize);
                    read_file_into_memory(get_cluster(dt->DIR_FstClusLO, dt->DIR_FstClusHI), file_data, dt->DIR_FileSize, addr);
                    //printf("f: %s\n", file_data);
                    //printf("size: %d\n", dt->DIR_FileSize);
                    unsigned char md[SHA_DIGEST_LENGTH];
                    SHA1(file_data, dt->DIR_FileSize, md);
                    char sha1_string[SHA_DIGEST_LENGTH * 2 + 1];
                    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                        sprintf(&sha1_string[i * 2], "%02x", md[i]);
                    }
                    if (strncmp(sha1_string, sha, SHA_DIGEST_LENGTH * 2) == 0) {
                        correct_fat_chain(get_cluster(dt->DIR_FstClusLO, dt->DIR_FstClusHI), dt->DIR_FileSize);
                         dt->DIR_Name[0] = *recovery_file_name;
                        printf("%s: successfully recovered with SHA-1\n", recovery_file_name);
                        return;
                    }
                                
                }
                
            }
            dt++;
            total_entries--;
            
            }
        temp_root_clstr = fat1[temp_root_clstr];
        
        }
        printf("%s: file not found\n", recovery_file_name);
        return;

    }
    
}

void correct_fat_chain(int start_clstr, int file_size) {
    int cluster_size_bytes = bt->BPB_SecPerClus * bt->BPB_BytsPerSec;
    int clusters_needed = (file_size + cluster_size_bytes - 1) / cluster_size_bytes;
    int current_cluster = start_clstr;
    for (int i = 0; i < clusters_needed; i++) {
        fat1[current_cluster] = (i == clusters_needed - 1) ? 0x0FFFFFFF : current_cluster + 1;
        current_cluster++;
    }
}

int count_match(char *recovery_file_name, char *addr) {
    unsigned int temp_root_clstr = root_cluster;
    int c=0;
    while(temp_root_clstr < 0x0ffffff8 ) {
        DirEntry *dt = (DirEntry *)(addr+get_cluster_address(temp_root_clstr));
        int total_entries = (bt->BPB_SecPerClus*bt->BPB_BytsPerSec)/32;
        //printf("clstr: %d\n", temp_root_clstr);

        while(dt->DIR_Name[0] != 0x00 && total_entries>0) {
            if(dt->DIR_Name[0] == 0xE5) {
                //char *t = (get_name(dt->DIR_Name,0)+1);

                if(strcmp((get_name(dt->DIR_Name,0)+1),(recovery_file_name+1))==0) {
                    c++;
                }
            }
            dt++;
            total_entries--;
        }
        temp_root_clstr = fat1[temp_root_clstr];
    }
    return c;
}

void read_file_into_memory(unsigned int start_cluster, unsigned char *buffer, size_t file_size, const char *addr) {
    size_t bytes_read = 0;
    unsigned int cluster = start_cluster;
    unsigned int cluster_size = bt->BPB_BytsPerSec * bt->BPB_SecPerClus;
    while (bytes_read < file_size) {
        unsigned int cluster_address = get_cluster_address(cluster);
        size_t bytes_to_read = file_size - bytes_read;
        if (bytes_to_read > cluster_size) {
            bytes_to_read = cluster_size;
        } 

        memcpy(buffer + bytes_read, addr + cluster_address, bytes_to_read);
        bytes_read += bytes_to_read;
        cluster++;
    }
    buffer[file_size] = '\0';
    

}


/*References:

-https://stackoverflow.com/questions/11236216/coverting-unsigned-char-returned-from-sha1-to-a-string
-https://stackoverflow.com/questions/14531958/c-copying-directly-from-memory-using-memcpy
-https://stackoverflow.com/questions/21278008/copy-data-from-a-memory-address-to-another-memory-address-752-bytes-at-a-time
*/