#include <stdlib.h>
#include <stdio.h>

typedef unsigned char            BYTE;
typedef unsigned short int       WORD;
typedef unsigned long int        LONG;
typedef unsigned long long int   DWORD;

#define IMAGE_DOS_SIGNATURE         0x5A4D              //MZ


#define IMAGE_NT_SIGNATURE          0x00004550          //PE00


/** x64 Processors */
#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
#define IMAGE_REL_AMD64_REL32       0x0004
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

/** ARM Processors */
#define IMAGE_REL_ARM_ABSOLUTE      0x0000
#define IMAGE_REL_ARM_ADDR32        0x0001
#define IMAGE_REL_ARM_ADDR32NB      0x0002
#define IMAGE_REL_ARM_BRANCH24      0x0003
#define IMAGE_REL_ARM_BRANCH11      0x0004
#define IMAGE_REL_ARM_SECTION       0x000E
#define IMAGE_REL_ARM_SECREL        0x000F
#define IMAGE_REL_ARM_MOV32         0x0010
#define IMAGE_REL_THUMB_MOV32       0x0011
#define IMAGE_REL_THUMB_BRANCH20    0x0012
#define Unused                      0x0013
#define IMAGE_REL_THUMB_BRANCH24    0x0014
#define IMAGE_REL_THUMB_BLX23       0x0015
#define IMAGE_REL_ARM_PAIR          0x0016

/** ARM64 Processors */
#define IMAGE_REL_ARM64_ABSOLUTE    0x0000
#define IMAGE_REL_ARM64_ADDR32      0x0001
#define IMAGE_REL_ARM64_ADDR32NB    0x0002
#define IMAGE_REL_ARM64_BRANCH26    0x0003
#define IMAGE_REL_ARM64_PAGEBASE_REL21  0x0004
#define IMAGE_REL_ARM64_REL21       0x0005
#define IMAGE_REL_ARM64_PAGEOFFSET_12A  0x0006
#define IMAGE_REL_ARM64_PAGEOFFSET_12L  0x0007
#define IMAGE_REL_ARM64_SECREL      0x0008
#define IMAGE_REL_ARM64_SECREL_LOW12A   0x0009
#define IMAGE_REL_ARM64_SECREL_HIGH12A  0x000A
#define IMAGE_REL_ARM64_SECREL_LOW12L   0x000B
#define IMAGE_REL_ARM64_TOKEN       0x000C
#define IMAGE_REL_ARM64_SECTION     0x000D
#define IMAGE_REL_ARM64_ADDR64      0x000E
#define IMAGE_REL_ARM64_BRANCH19    0x000F
#define IMAGE_REL_ARM64_BRANCH14    0x0010

/** Intel 386 Processors */
#define IMAGE_REL_I386_ABSOLUTE 0x0000
#define IMAGE_REL_I386_DIR16    0x0001
#define IMAGE_REL_I386_REL16    0x0002
#define IMAGE_REL_I386_DIR32    0x0006
#define IMAGE_REL_I386_DIR32NB  0x0007
#define IMAGE_REL_I386_SEG12    0x0009
#define IMAGE_REL_I386_SECTION  0x000A
#define IMAGE_REL_I386_SECREL   0x000B
#define IMAGE_REL_I386_TOKEN    0x000C
#define IMAGE_REL_I386_SECREL7  0x000D
#define IMAGE_REL_I386_REL32    0x0014


typedef struct _IMAGE_DOS_HEADER {　　　　// DOS .EXE header
　　WORD　 e_magic;　　　　　　　　　　　　　// Magic number
　　WORD　 e_cblp;　　　　　　　　　　　　　 // Bytes on last page of file
　　WORD　 e_cp;　　　　　　　　　　　　　　 // Pages in file
　　WORD　 e_crlc;　　　　　　　　　　　　　 // Relocations
　　WORD　 e_cparhdr;　　　　　　　　　　　 // Size of header in paragraphs
　　WORD　 e_minalloc;　　　　　　　　　　  // Minimum extra paragraphs needed
　　WORD　 e_maxalloc;　　　　　　　　　　  // Maximum extra paragraphs needed
　　WORD　 e_ss;　　　　　　　　　　　　    // Initial (relative) SS value
　　WORD　 e_sp;　　　　　　　　　　　　    // Initial SP value
　　WORD　 e_csum;　　　　　　　　　　　　  // Checksum
　　WORD　 e_ip;　　　　　　　　　　　　    // Initial IP value
　　WORD　 e_cs;　　　　　　　　　　　　    // Initial (relative) CS value
　　WORD　 e_lfarlc;　　　　　　　　　　   // File address of relocation table
　　WORD　 e_ovno;　　　　　　　　　　　　  // Overlay number
　　WORD　 e_res[4];　　　　　　　　　　   // Reserved words
　　WORD　 e_oemid;　　　　　　　　　　    // OEM identifier (for e_oeminfo)
　　WORD　 e_oeminfo;　　　　　　　　　　  // OEM information; e_oemid specific
　　WORD　 e_res2[10];　　　　　　　　　　 // Reserved words
　　LONG　 e_lfanew;　　　　　　　　　　   // File address of new exe header
　} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_NT_HEADERS{
    DWORD   Sifnature;                          //pe flag
    IMAGE_FILE_HEADER   FileHeader;             //file header
    IMAGE_OPIONAL_HEADER32  OptionalHeader;     //optinal header
}IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#define IMAGE_FILE_MACHINE_UNKNOWN      0x0001      //unknown
#define IMAGE_FILE_MACHINE_AM33         0x01d3      //Matsushita AM33
#define IMAGE_FILE_MACHINE_AMD64        0x8664      //x64
#define IMAGE_FILE_MACHINE_ARM          0x01c0      //ARM little endian
#define IMAGE_FILE_MACHINE_ARM64        0xaa64      //ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT        0x01c4      //ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_EBC          0x0ebc      //EFI byte code
#define IMAGE_FILE_MACHINE_I386         0x014c      //Intel
#define IMAGE_FILE_MACHINE_ALPHA        0x0184      //DEC Alpha
#define IMAGE_FILE_MACHINE_IA64         0x0200      //Intel (64-bit)
#define IMAGE_FILE_MACHINE_AXP64        0x0284      //DEC Alpha (64-bit)
#define IMAGE_FILE_MACHINE_M32R         0x9041
#define IMAGE_FILE_MACHINE_MIPS16       0x0266
#define IMAGE_FILE_MACHINE_MIPSFPU      0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16    0x0466
#define IMAGE_FILE_MACHINE_POWERPC      0x01f0
#define IMAGE_FILE_MACHINE_POWERPCFP    0x01f1
#define IMAGE_FILE_MACHINE_R4000        0x0166
#define IMAGE_FILE_MACHINE_RISCV32      0x5032
#define IMAGE_FILE_MACHINE_RISCV64      0x5064
#define IMAGE_FILE_MACHINE_RISCV128     0x5128
#define IMAGE_FILE_MACHINE_SH3          0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP       0x01a3
#define IMAGE_FILE_MACHINE_SH4          0x01a6
#define IMAGE_FILE_MACHINE_SH5          0x01a8
#define IMAGE_FILE_MACHINE_THUMB        0x01c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2    0x0169



#define IMAGE_FILE_RELOCS_STRIPPED      0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE     0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED   0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED  0x0008
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM   0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE  0x0020
#define IMAGE_FILE_RESERVED             0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO    0x0080
#define IMAGE_FILE_32BIT_MACHINE        0x0100
#define IMAGE_FILE_DEBUG_STRIPPED       0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP    0x0800
#define IMAGE_FILE_SYSTEM               0x1000
#define IMAGE_FILE_DLL                  0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY       0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI    0x8000

/** Windows Subsystem */
#define IMAGE_SUBSYSTEM_UNKNOWN             0
#define IMAGE_SUBSYSTEM_NATIVE              1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI         2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI         3
#define IMAGE_SUBSYSTEM_OS2_CUI             5
#define IMAGE_SUBSYSTEM_POSIX_CUI           7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS      8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI      9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION     10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER  12
#define IMAGE_SUBSYSTEM_EFI_ROM             13
#define IMAGE_SUBSYSTEM_XBOX                14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16


#define IMAGE_DIRECTORY_ENTRY_EXPORT                0
#define IMAGE_DIRECTORY_ENTRY_IMPORT                1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE              2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION             3
#define IMAGE_DIRECTORY_ENTRY_SECURITY              4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC             5
#define IMAGE_DIRECTORY_ENTRY_DEBUG                 6

#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE          7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR             8
#define IMAGE_DIRECTORY_ENTRY_TLS                   9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG           10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT          11
#define IMAGE_DIRECTORY_ENTRY_IAT                   12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT          13
#define IMAGE_DIRECTORY_COM_DESCRIPTOR              14

typedef struct _IMAGE_FILE_HEADER{
    WORD    Machine;                //platform
    WORD    NumberOfSection;        //section number
    DWORD   TimeDateStamp;          //create time
    DWORD   PointerToSymbolTable;   //symbol table pointer
    DWORD   NumberOfSymbols;        //symbol table numbers
    WORD    SizeOfOptionalHeader;   //optional header size
    WORD    Characteristics;        //file property
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


typedef struct _IMAGE_OPTIONAL_HEADER {
　　
    // Standard fields.
　　WORD　　Magic;                              //flag word ,rom(0x0107),others(0x010B)
　　BYTE　　MajorLinkerVersion;                 //
　　BYTE　　MinorLinkerVersion;
　　DWORD　 SizeOfCode;
　　DWORD　 SizeOfInitializedData;
　　DWORD　 SizeOfUninitializedData;
　　DWORD　 AddressOfEntryPoint;
　　DWORD　 BaseOfCode;
　　DWORD　 BaseOfData;

　　// NT additional fields.
　　DWORD　 ImageBase;
　　DWORD　 SectionAlignment;
　　DWORD　 FileAlignment;
　　WORD　　MajorOperatingSystemVersion;
　　WORD　　MinorOperatingSystemVersion;
　　WORD　　MajorImageVersion;
　　WORD　　MinorImageVersion;
　　WORD　　MajorSubsystemVersion;
　　WORD　　MinorSubsystemVersion;
　　DWORD　 Win32VersionValue;
　　DWORD　 SizeOfImage;
　　DWORD　 SizeOfHeaders;
　　DWORD　 CheckSum;
　　WORD　　Subsystem;
　　WORD　　DllCharacteristics;
　　DWORD　 SizeOfStackReserve;
　　DWORD　 SizeOfStackCommit;
　　DWORD　 SizeOfHeapReserve;
　　DWORD　 SizeOfHeapCommit;
　　DWORD　 LoaderFlags;
　　DWORD　 NumberOfRvaAndSizes;
　　IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES　　16

typedef struct _IMAGE_DATA_DIRECTORY {
　　DWORD　 VirtualAddress;
　　DWORD　 Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_SIZEOF_SECTION_HEADER　　　　　40
#define IMAGE_SIZEOF_SHORT_NAME　　　　　　　8

typedef struct _IMAGE_SECTION_HEADER {
　　BYTE　　Name[IMAGE_SIZEOF_SHORT_NAME];
　　union {
　　　　　　DWORD　 PhysicalAddress;
　　　　　　DWORD　 VirtualSize;
　　} Misc;
　　DWORD　 VirtualAddress;
　　DWORD　 SizeOfRawData;
　　DWORD　 PointerToRawData;
　　DWORD　 PointerToRelocations;
　　DWORD　 PointerToLinenumbers;
　　WORD　　NumberOfRelocations;
　　WORD　　NumberOfLinenumbers;
　　DWORD　 Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

/** Export table */
typedef  struct  _IMAGE_EXPORT_DIRECTORY{
    DWORD  Characteristics;
    DWORD  TimeDateStamp;          
    DWORD  MajorVersion;           
    DWORD  MinorVersion;           
    DWORD  Name;                  
    DWORD   Base;                  
    DWORD   NumberOfFunctions;     
    DWORD   NumberOfNames;  
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;        
    DWORD   AddressOfNameOrdinals;
}IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

/** Import table */
typedef struct  _IMAGE_IMPORT_DESCRIPTOR{
    union{
        DWORD  Characteristics;
        DWORD  OriginalFirstThunk;  
    };
    DWORD  TimoeDateStamp;   
    DWORD  ForwaiderChain;
    DWORD  Name;
    DWORD  FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMSGE_IMPORT_DESCRIPTOR;

/** Resource table */
typedef  struct  _IMAGE_RESOURCE_DIRECTORY{
    DWORD  Characteristics;    
    DWORD  TimeDateStamp;  
    WORD   MajorVersion;      
    WORD   MinorVersion;       
    WORD   NumberOfNamedEntries;  
    WORD   NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

/** Relocate table */
typedef  struct  _IMAGE_BASE_RELOCATION{
    DWORD  VirtualAddress;    
    DWORD  SizeOfBloce; 
}IMAGE_BASE_RELOCATION;
typedef  IMAGE_BASE_RELOCATION  UNALIGNED  * PIMAGE_BASE_RELOCATION;


/** Debug */
typedef struct _IMAGE_DEBUG_DIRECTORY
{
    DWORD Characteristics;   //保留
    DWORD TimeDateStamp;     //日期与时间
    WORD  MajorVersion;      //主版本号
    WORD  MinorVersion;      //子版本号
    DWORD Type;              //调试信息格式
    DWORD SizeOfData;        //调试数据的大小
    DWORD AddressOfRawData;  //加载到内存时的调试数据RAV
    DWORD PointerToRawData;  //调试数据的文件偏移
}IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;