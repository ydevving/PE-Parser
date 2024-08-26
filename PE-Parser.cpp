
#include <iostream>
#include <fstream>
#include <windows.h>

#define MAGENTA "\033[35m"
#define RESET   "\033[0m"

int main(int argc, char* argv[])
{
    if (argc < 2)
        return -1;

    std::ifstream pe;
    pe.open(argv[1], std::ifstream::out || std::ifstream::binary);

    if (!pe.is_open())
        return -1;

    std::cout << argc << "\n";
    
    for (int i = 0; i < argc; i++) {
        std::cout << argv[i] << std::endl;
    }

    // get pointer to associated buffer object
    std::filebuf* pbuf = pe.rdbuf();

    // get file size using buffer's members
    std::size_t size = pbuf->pubseekoff(0, pe.end, pe.in);
    pbuf->pubseekpos(0, pe.in);

    // allocate memory to contain file data
    char* buffer = new char[size];

    // get file data
    pbuf->sgetn(buffer, size);

    pe.close();

    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)buffer;
    
    std::cout << MAGENTA;
    printf("\nImage Dos Header\n\n");
    std::cout << RESET;
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


    printf("\n");
    delete[] buffer;

    return 0;
}
