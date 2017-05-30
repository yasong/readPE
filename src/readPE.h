#include <stdlib.h>
#include <stdio.h>

typedef short int       WORD;
typedef long int        LONG;
typedef long long int   DWORD;

#define IMAGE_DOS_SIGNATURE         0x5A4D              //MZ


#define IMAGE_NT_SIGNATURE          0x00004550          //PE00

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


typedef struct _IMAGE_FILE_HEADER{
    WORD    Machine;                //platform
    WORD    NumberOfSection;        //section number
    DWORD   TimeDateStamp;          //create time
    DWORD   PointerToSymbolTable;   //symbol table pointer
    DWORD   NumberOfSymbols;        //symbol table numbers
    WORD    SizeOfOptionalHeader;   //optional header size
    WORD    Characteristics;        //file property
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS{
    DWORD   Sifnature;                          //pe flag
    IMAGE_FILE_HEADER   FileHeader;             //file header
    IMAGE_OPIONAL_HEADER32  OptionalHeader;     //optinal header
}IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

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

