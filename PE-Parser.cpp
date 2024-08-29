
#include <iostream>
#include <fstream>
#include <windows.h>
#include <map>


#define MAGENTA "\033[35m"
#define RESET   "\033[0m"


#define DOS_HEADER_M      1
#define DOS_STUB_M        2

// NT Headers
#define SIGNATURE_M       3
#define FILE_HEADER_M     4
#define OPTIONAL_HEADER_M 5

#define SECTION_HEADER_M  6

/*
    TO-DO:
    Import all windows PE structs when im done to make it cross compatible so you dont need to include windows.h
*/

int main(int argc, char* argv[])
{
    //if (argc < 2)
    //    return -1;

    std::ifstream pe_file;
    //pe_file.open(argv[1], std::ifstream::out || std::ifstream::binary);
    pe_file.open("Vectors.exe", std::ifstream::out || std::ifstream::binary);

    if (!pe_file.is_open())
        return -1;

    // get pointer to associated buffer object
    std::filebuf* pbuf = pe_file.rdbuf();

    // get file size using buffer's members
    std::size_t size = pbuf->pubseekoff(0, pe_file.end, pe_file.in);
    pbuf->pubseekpos(0, pe_file.in);

    // allocate memory to contain file data
    char* buffer = new char[size];

    // get file data
    pbuf->sgetn(buffer, size);

    pe_file.close();

    std::map<int, void*> pe;

    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)buffer;

    printf("\nImage Dos Header\n\n");
    printf("Magic number - %x\n", dos_header->e_magic);
    printf("Bytes on last page of file - %x\n", dos_header->e_cblp);
    printf("Pages in file - %x\n", dos_header->e_cp);
    printf("Relocations - %x\n", dos_header->e_crlc);
    printf("Size of header in paragraphs - %x\n", dos_header->e_cparhdr);
    printf("Minimum extra paragraphs needed - %x\n", dos_header->e_minalloc);
    printf("Maximum extra paragraphs needed - %x\n", dos_header->e_maxalloc);
    printf("Initial (relative) SS value - %x\n", dos_header->e_ss);
    printf("Initial SP value - %x\n", dos_header->e_sp);
    printf("Checksum - %x\n", dos_header->e_csum);
    printf("Initial IP value - %x\n", dos_header->e_ip);
    printf("Initial (relative) CS value - %x\n", dos_header->e_cs);
    printf("File address of relocation table - %x\n", dos_header->e_lfarlc);
    printf("Overlay number - %x\n", dos_header->e_ovno);
    printf("OEM identifier - %x\n", dos_header->e_oemid);
    printf("OEM information - %x\n", dos_header->e_oeminfo);
    printf("File address of new exe header - %x\n", dos_header->e_lfanew);

    long dos_header_addr = long(dos_header);
    long lfa = long(&dos_header->e_lfanew);
    long nt_offset = dos_header->e_lfanew;

    long stub_length = nt_offset - (lfa - dos_header_addr + sizeof(nt_offset));
    long stub_offset = nt_offset + sizeof(nt_offset);
    
    char* dos_stub = new char[stub_length];
    std::cout << std::hex << &dos_header << std::dec << std::endl;

    // WHY DOES MEMCPY ERRORS ALL THE TIME
    //std::memcpy(dos_stub, (void*)long(buffer + stub_offset), stub_length);

    printf("0x%016X\n", stub_length);

    printf("\n");
    delete[] dos_stub;
    delete[] buffer;

    return 0;
}
