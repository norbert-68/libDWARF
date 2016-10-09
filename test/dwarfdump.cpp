/*******************************************************************************
 * Copyright (C) 2012..2016 norbert.klose@web.de
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/

#include <MachO.hpp>
#include <DWARF.hpp>
#include <ELF.hpp>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <getopt.h>

typedef std::vector<std::string> Filenames;

struct ProgramOptions
{
    Filenames filenames;
    bool debugLine;
    bool verbose;

    ProgramOptions() :
        debugLine(false),
        verbose(false)
    {}

} programOptions;

void usage(const char * programName)
{
    std::cout << "usage: " << programName << " [option]*" << std::endl
              << std::endl
              << "where option may" << std::endl
              << std::endl
              << " FILENAME         filename of an object file to be processed" << std::endl
              << " -L,--debug-line  print .debug_line section"                  << std::endl
              << " -v,--verbose     be more verbose"                            << std::endl
              << " -?,--help        print this help overview"                   << std::endl;
}

int parseProgramOptions(int argc, char * args[])
{
    int result = EXIT_SUCCESS;

    static struct option longOptions[] =
    {
        { "debug-line", no_argument, 0, 'L' },
        { "verbose"   , no_argument, 0, 'v' },
        { "help"      , no_argument, 0, '?' },
        { 0           , 0          , 0,  0  }
    };

    int nextOption;
    while ((nextOption = getopt_long(argc, args, "v?", longOptions, 0)) != -1 && result == EXIT_SUCCESS)
    {
        switch (nextOption)
        {
            case 'L':
                programOptions.debugLine = true;
                break;
            case 'v':
                programOptions.verbose = true;
                break;
            case '?':
            default:
                usage(args[0]);
                result = EXIT_FAILURE;
                break;
        }
    }

    if (result == EXIT_SUCCESS)
    {
        // take all unprocessed commandline arguments as FILENAME
        while (optind < argc)
            programOptions.filenames.push_back(args[optind++]);
    }

    return result;
}

int main(int argc, char * args[])
{
    try
    {
        if (parseProgramOptions(argc, args) != EXIT_SUCCESS)
            return EXIT_FAILURE;

        for (const std::string & filename : programOptions.filenames)
        {
            dwarf::LineNumberSection lineNumberSection;

            if (elf::ELFFile::isELF(filename))
            {
                elf::ELFFile elfFile;
                elfFile.open(filename);
                if (programOptions.debugLine)
                {
                    std::deque<elf::ELFSection> debugLine;
                    elfFile.findSections(dwarf::SN_DEBUG_LINE, debugLine);
                    for (const elf::ELFSection & section : debugLine)
                    {
                        std::cout << section.name << ":" << std::endl;
//                        if (programOptions.verbose)
//                            std::cout << common::hexdump(section.binaryContent, section.binaryLength) << std::endl;
                        lineNumberSection.deserialize(section.binaryContent, section.binaryLength,
                                                      elfFile.header.elfEndianness == elf::ELF_DATA2LSB,
                                                      elfFile.header.elfClass == elf::ELF_CLASS64);
                    }
                }
            }
            else if (macho::MachOFile::isMachO(filename))
            {
                macho::MachOFile machoFile;
                machoFile.open(filename);
                if (programOptions.debugLine)
                {
                    std::deque<const macho::MachOSection*> debugLine;
                    machoFile.findSections(dwarf::SN_DEBUG_LINE_MACHO, debugLine);
                    for (const macho::MachOSection * section : debugLine)
                    {
                        std::cout << section->sectionName << ":" << std::endl;
//                        if (programOptions.verbose)
//                            std::cout << common::hexdump(section->data(), section->	size()) << std::endl;
                        lineNumberSection.deserialize(section->data(), section->size(),
                                                      machoFile.header.isLittleEndian(),
                                                      machoFile.header.is64Bit());
                    }
                }
            }

            if (programOptions.debugLine)
            {
                std::cout << lineNumberSection << std::endl;
            }
        }
    }
    catch (const std::exception & exception)
    {
        std::cerr << "ERROR: " << exception.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (...)
    {
        std::cerr << "ERROR: unknown exception" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
