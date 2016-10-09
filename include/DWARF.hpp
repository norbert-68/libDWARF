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
#ifndef DWARF_HPP
#define DWARF_HPP

#include <ELF.hpp>
#include <MachO.hpp>
#include <iomanip>
#include <map>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>
#include <cassert>
#include <cstdint>

namespace dwarf {

typedef int8_t   DWARFSByte;
typedef uint8_t  DWARFUByte;
typedef int16_t  DWARFSHalf;
typedef uint16_t DWARFUHalf;
typedef uint32_t DWARFUWord;
typedef int32_t  DWARFSWord;
typedef uint64_t DWARFUDWord;
typedef int64_t  DWARFSDWord;

const char * const SN_DEBUG_LINE       = ".debug_line";
const char * const SN_DEBUG_LINE_MACHO = "__debug_line";

template<typename Int>
Int readInteger(const uint8_t * src, bool littleEndian)
{
    Int result = 0;
    if (src)
        for (std::size_t i = 0; i < sizeof(Int); ++i)
            result += static_cast<Int>(src[i]) << (littleEndian ? i * 8 : (sizeof(Int) - i - 1) * 8);
    return result;
}

template<typename Int>
Int readInteger(const uint8_t * & src, std::size_t & length, bool littleEndian, const char * name)
{
    if (length < sizeof(Int))
        throw std::runtime_error(name);
    Int result = readInteger<Int>(src, littleEndian);
    src += sizeof(Int);
    length -= sizeof(Int);
    return result;
}

/**
 * @brief Reads an unsigned Little Endian Base 128 encoded value.
 */
template<typename Int>
Int readULEB128(const uint8_t * & src, std::size_t & length, bool littleEndian, const char * name)
{
    Int result = 0;
    std::size_t shift = 0;
    DWARFUByte byte = 0;
    while (true)
    {
        if (length < sizeof(uint8_t))
            throw std::runtime_error(name);
        byte = *src;
        src += sizeof(uint8_t);
        length -= sizeof(uint8_t);
        result |= ((byte & static_cast<DWARFUDWord>(0x7F)) << shift);
        if ((byte & 0x80) == 0)
              break;
        shift += 7;
    }
    return result;
}

/**
 * @brief Reads a signed Little Endian Base 128 encoded value.
 */
template<typename Int>
Int readSLEB128(const uint8_t * & src, std::size_t & length, bool littleEndian, const char * name)
{
    Int result = 0;
    std::size_t shift = 0;
    DWARFUByte byte = 0;
    while (true)
    {
        if (length < sizeof(uint8_t))
            throw std::runtime_error(name);
        byte = *src;
        src += sizeof(uint8_t);
        length -= sizeof(uint8_t);
        result |= ((byte & static_cast<DWARFUDWord>(0x7F)) << shift);
        shift += 7;
        if ((byte & 0x80) == 0)
            break;
    }
    if ((shift < (sizeof(DWARFSDWord) * 8)) && (byte & 0x40)) // sign bit set?
        result |= - (1 << shift);
    return result;
}

/**
 * @brief The InitialLength structure.
 *
 * An initial length field is one of the length fields that occur at the beginning of
 * those DWARF sections that have a header (.debug_aranges, .debug_info, .debug_types,
 * .debug_line, .debug_pubnames, and .debug_pubtypes) or the length field that occurs
 * at the beginning of the CIE and FDE structures in the .debug_frame section.
 *
 * In an initial length field, the values 0xfffffff0 through 0xffffffff are reserved
 * by DWARF to indicate some form of extension relative to DWARF Version 2; such values
 * must not be interpreted as a length field.
 *
 * The differences between the 32- and 64-bit DWARF formats are detailed in the following:
 * 1. In the 32-bit DWARF format, an initial length field is an unsigned 32-bit integer
 *    (which must be less than 0xfffffff0)
 * 2. In the 64-bit DWARF format, an initial length field is 96 bits in size, and has two
 *    parts:
 *    - The first 32-bits have the value 0xffffffff.
 *    - The following 64-bits contain the actual length represented as an unsigned 64-bit
 *      integer.
 * This representation allows a DWARF consumer to dynamically detect that a DWARF section
 * contribution is using the 64-bit format and to adapt its processing accordingly.
 */
struct InitialLength
{
    DWARFUDWord value;
    bool is64Bit;

    InitialLength(DWARFUDWord value = 0, bool is64Bit = false) :
        value(value),
        is64Bit(is64Bit) {}

    void deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian);
};

struct LineNumberOpcode
{
    DWARFUByte code;
    DWARFUByte length;

    enum {
        DW_LNS_copy = 1,
        DW_LNS_advance_pc = 2,
        DW_LNS_advance_line = 3,
        DW_LNS_set_file = 4,
        DW_LNS_set_column = 5,
        DW_LNS_negate_stmt = 6,
        DW_LNS_set_basic_block = 7,
        DW_LNS_const_add_pc = 8,
        DW_LNS_fixed_advance_pc = 9,
        DW_LNS_set_prologue_end = 10,
        DW_LNS_set_epilogue_begin = 11,
        DW_LNS_set_isa = 12,
    };

    LineNumberOpcode(DWARFUByte code = 0, DWARFUByte length = 0) :
        code(code),
        length(length) {}

    void deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian);

    static const char * getName(DWARFUHalf opcode);
};

/**
 * @brief These have a multiple byte format. The first byte is zero; the next bytes are an unsigned LEB128 integer giving the number of bytes in the
instruction itself (does not include the first zero byte or the size). The remaining bytes are the instruction itself (which begins with a ubyte extended opcode).
 */
struct LineNumberExtendedOpcode
{
    DWARFUWord length;
    DWARFUByte code;

    enum {
        DW_LNE_end_sequence = 1,
        DW_LNE_set_address = 2,
        DW_LNE_define_file = 3,
        DW_LNE_set_discriminator = 4
    };

    LineNumberExtendedOpcode() :
        length(0),
        code(0) {}

    void deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian);

    static const char * getName(DWARFUHalf opcode);
};

/**
 * @brief A DWARF Line Number Program Header file name entry.
 */
struct LineNumberFileName
{
    std::string filename;
    DWARFUWord directoryIndex;
    DWARFUDWord modificationTime;
    DWARFUDWord fileLength;

    void deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian);
};

/**
 * @brief The LineNumberProgramHeader structure.
 *
 * The line number program header provides information used by consumers in decoding the
 * line number program instructions for a particular compilation unit and also provides
 * information used throughout the rest of the line number program.
 *
 * The line number program for each compilation unit begins with a @e LineNumberProgramHeader.
 */
struct LineNumberProgramHeader
{
    /**
     * @brief The size in bytes of the line number information for this compilation unit,
     * not including the unitLength field itself.
     */
    InitialLength unitLength;

    /**
     * @brief A version number (either 2, 3 or 4). This number is specific to the line number
     * information and is independent of the DWARF version number.
     */
    DWARFUHalf version;

    /**
     * @brief The number of bytes following the @e headerLength field to the beginning of the
     * first byte of the line number program itself. In the 32-bit DWARF format, this is a
     * 4-byte unsigned length; in the 64-bit DWARF format, this field is an 8-byte unsigned
     * length.
     */
    DWARFUDWord headerLength;

    /**
     * @brief The size in bytes of the smallest target machine instruction. Line number program
     * opcodes that alter the @e address and @e opIndex registers use this and
     * @e maximumOperationsPerInstruction in their calculations.
     */
    DWARFUByte minimumInstructionLength;

    /**
     * @brief The maximum number of individual operations that may be encoded in an instruction.
     * Line number program opcodes that alter the @e address and @€ opIndex registers use this
     * and @e minimumInstructionLength in their calculations.
     * For non-Very Long Instruction Word (VLIW) architectures, this field is 1, the @e opIndex
     * register is always 0, and the operation pointer is simply the address register.
     */
    DWARFUByte maximumOperationsPerInstruction;

    /**
     * @brief The initial value of the is_stmt register.
     */
    DWARFUByte defaultIsStmt;

    /**
     * @brief This parameter affects the meaning of the special opcodes.
     */
    DWARFSByte lineBase;

    /**
     * @brief This parameter affects the meaning of the special opcodes.
     */
    DWARFUByte lineRange;

    /**
     * @brief The number assigned to the first special opcode.
     * @e opcodeBase is typically one greater than the highest-numbered standard opcode defined
     * for the specified version of the line number information (12 in DWARF Version 3 and
     * Version 4, 9 in Version 2). If @e opcodeBase is less than the typical value, then standard
     * opcode numbers greater than or equal to the opcode base are not used in the line number
     * table of this unit (and the codes are treated as special opcodes).
     * If @e opcodeBase is greater than the typical value, then the numbers between that of the
     * highest standard opcode and the first special opcode (not inclusive) are used for vendor
     * specific extensions.
     */
    DWARFUByte opcodeBase;

    /**
     * @brief This array specifies the number of LEB128 operands for each of the standard opcodes.
     * The first element of the array corresponds to the opcode whose value is 1, and the last
     * element corresponds to the opcode whose value is @e opcodeBase - 1.
     * By increasing @e opcodeBase, and adding elements to this array, new standard opcodes can be
     * added, while allowing consumers who do not know about these new opcodes to be able to skip
     * them.
     * Codes for vendor specific extensions, if any, are described just like standard opcodes.
     */
    std::vector<LineNumberOpcode> standardOpcodeLengths;

    /**
     * @brief Entries in this sequence describe each path that was searched for included source
     * files in this compilation. (The paths include those directories specified explicitly by
     * the user for the compiler to search and those the compiler searches without explicit
     * direction).
     * Each path entry is either a full path name or is relative to the current directory of the
     * compilation.
     * The last entry is followed by a single null byte.
     * The line number program assigns numbers to each of the file entries in order, beginning
     * with 1. The current directory of the compilation is understood to be the zeroth entry and
     * is not explicitly represented.
     */
    std::vector<std::string> includeDirectories;

    /**
     * @brief Entries in this sequence describe source files that contribute to the line number
     * information for this compilation unit.
     * The last entry is followed by a single null byte.
     * The directory index represents an entry in the include_directories section. The index is 0
     * if the file was found in the current directory of the compilation, 1 if it was found in the
     * first directory in the @e includeDirectories section, and so on.
     * The directory index is ignored for file names that represent full path names.
     */
    std::vector<LineNumberFileName> fileNames;

    LineNumberProgramHeader() :
        version(2),
        headerLength(0),
        minimumInstructionLength(1),
        maximumOperationsPerInstruction(1),
        defaultIsStmt(0),
        lineBase(1),
        lineRange(1),
        opcodeBase(13) {}

    void deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian);
};

// Forward Declaration
struct LineNumberUnit;

/**
 * @brief LineNumberRow structure.
 */
struct LineNumberRow
{
    LineNumberUnit * lineNumberUnit;

    /**
     * @brief The program-counter value corresponding to a machine instruction generated by the compiler.
     */
    DWARFUDWord address;

    /**
     * @brief An unsigned integer representing the index of an operation within a Very Long Instruction
     * Word (VLIW) instruction. The index of the first operation is @c 0. For non-VLIW architectures,
     * this register will always be @c 0.
     */
    DWARFUWord opIndex;

    /**
     * @brief An unsigned integer indicating the identity of the source file corresponding to a machine
     * instruction.
     */
    DWARFUWord file;

    /**
     * @brief An unsigned integer indicating a source line number. Lines are numbered beginning at @c 1.
     * The compiler may emit the value @c 0 in cases where an instruction cannot be attributed to any
     * source line.
     */
    DWARFUWord line;

    /**
     * @brief An unsigned integer indicating a column number within a source line. Columns are numbered
     * beginning at @c 1. The value @c 0 is reserved to indicate that a statement begins at the “left
     * edge” of the line.
     */
    DWARFUWord column;

    /**
     * @brief A boolean indicating that the current instruction is a recommended breakpoint location.
     * A recommended breakpoint location is intended to “represent” a line, a statement and/or a
     * semantically distinct subpart of a statement.
     */
    bool isStmt;

    /**
     * @brief A boolean indicating that the current instruction is the beginning of a basic block.
     */
    bool basicBlock;

    /**
     * @brief A boolean indicating that the current address is that of the first byte after the end of
     * a sequence of target machine instructions. @e endSequence terminates a sequence of lines;
     * therefore other information in the same row is not meaningful.
     */
    bool endSequence;

    /**
     * @brief A boolean indicating that the current address is one (of possibly many) where execution
     * should be suspended for an entry breakpoint of a function.
     */
    bool prologueEnd;

    /**
     * @brief A boolean indicating that the current address is one (of possibly many) where execution
     * should be suspended for an exit breakpoint of a function.
     */
    bool epilogueBegin;

    /**
     * @brief An unsigned integer whose value encodes the applicable instruction set architecture for
     * the current instruction.
     * The encoding of instruction sets should be shared by all users of a given architecture. It is
     * recommended that this encoding be defined by the ABI authoring committee for each architecture.
     */
    DWARFUHalf isa;

    /**
     * @brief An unsigned integer identifying the block to which the current instruction belongs.
     * Discriminator values are assigned arbitrarily by the DWARF producer and serve to distinguish
     * among multiple blocks that may all be associated with the same source file, line, and column.
     * Where only one block exists for a given source position, the discriminator value should be
     * @c 0.
     */
    DWARFUHalf discriminator;

    LineNumberRow(LineNumberUnit * lineNumberUnit, bool isStmt) :
        lineNumberUnit(lineNumberUnit),
        address(0),
        opIndex(0),
        file(1),
        line(1),
        column(0),
        isStmt(isStmt),
        basicBlock(false),
        endSequence(false),
        prologueEnd(false),
        epilogueBegin(false),
        isa(0),
        discriminator(0) {}

    std::string getSourceLine() const;
};

/**
 * @brief LineNumberUnit
 */
struct LineNumberUnit : std::vector<LineNumberRow>
{
    LineNumberProgramHeader header;

    LineNumberUnit() {}

    LineNumberUnit(const LineNumberUnit & right) :
        std::vector<LineNumberRow>(right),
        header(right.header)
    {
        for (LineNumberRow & lineNumberRow : *this)
            lineNumberRow.lineNumberUnit = this;
    }

    void deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian, bool arch64Bit);

    LineNumberUnit & operator=(const LineNumberUnit & right)
    {
        std::vector<LineNumberRow>::operator=(right);
        for (LineNumberRow & lineNumberRow : *this)
            lineNumberRow.lineNumberUnit = this;
        header = right.header;
        return *this;
    }
};

/**
 * @brief The LineNumberSection structure.
 */
struct LineNumberSection : std::vector<LineNumberUnit>
{
    typedef std::map<DWARFUDWord, const LineNumberRow*> AddressIndex;
    AddressIndex addressIndex;

    AddressIndex::const_iterator addressToLine(uint64_t address) const
    {
        return addressIndex.lower_bound(address);
    }

    void clear()
    {
        std::vector<LineNumberUnit>::clear();
        addressIndex.clear();
    }

    void deserialize(const uint8_t * src, std::size_t length, bool littleEndian, bool arch64Bit);

    void deserialize(const std::string & filename);

};

} // namespace dwarf

std::ostream & operator<<(std::ostream & stream, const dwarf::InitialLength & right);
std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberProgramHeader & right);
std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberUnit & right);
std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberSection & right);

namespace dwarf {

inline void InitialLength::deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian)
{
    DWARFUWord value = readInteger<DWARFUWord>(src, length, littleEndian, "dwarf: initial length");
    is64Bit = value == 0xffffffff;
    if (is64Bit)
        this->value = readInteger<DWARFUDWord>(src, length, littleEndian, "dwarf: 64-bit initial length");
    else
        this->value = value;
}

inline void LineNumberOpcode::deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian)
{
    this->length = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number program: opcode length");
}

inline const char * LineNumberOpcode::getName(DWARFUHalf opcode)
{
    switch (opcode)
    {
    case DW_LNS_copy:               return "DW_LNS_copy";
    case DW_LNS_advance_pc:         return "DW_LNS_advance_pc";
    case DW_LNS_advance_line:       return "DW_LNS_advance_line";
    case DW_LNS_set_file:           return "DW_LNS_set_file";
    case DW_LNS_set_column:         return "DW_LNS_set_column";
    case DW_LNS_negate_stmt:        return "DW_LNS_negate_stmt";
    case DW_LNS_set_basic_block:    return "DW_LNS_set_basic_block";
    case DW_LNS_const_add_pc:       return "DW_LNS_const_add_pc";
    case DW_LNS_fixed_advance_pc:   return "DW_LNS_fixed_advance_pc";
    case DW_LNS_set_prologue_end:   return "DW_LNS_set_prologue_end";
    case DW_LNS_set_epilogue_begin: return "DW_LNS_set_epilogue_begin";
    case DW_LNS_set_isa:            return "DW_LNS_set_isa";
    }
    return 0;
}

inline void LineNumberExtendedOpcode::deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian)
{
    this->length = readULEB128<DWARFUWord>(src, length, littleEndian, "dwarf: line number extended opcode length");
    if (this->length == 0)
        this->code = 0;
    else
    {
        code = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number extended opcode");
        this->length -= sizeof(DWARFUByte);
    }
}

inline const char * LineNumberExtendedOpcode::getName(DWARFUHalf opcode)
{
    switch (opcode)
    {
    case DW_LNE_end_sequence:      return "DW_LNE_end_sequence";
    case DW_LNE_set_address:       return "DW_LNE_set_address";
    case DW_LNE_define_file:       return "DW_LNE_define_file";
    case DW_LNE_set_discriminator: return "DW_LNE_set_discriminator";
    }
    return 0;
}

inline void LineNumberFileName::deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian)
{
    filename = reinterpret_cast<const char*>(src);
    if (filename.length() + 1 > length)
        throw std::runtime_error("dwarf: line number program header: file name");
    src += filename.length() + 1;
    length -= filename.length() + 1;
    if (!filename.empty())
    {
        directoryIndex = readULEB128<DWARFUWord>(src, length, littleEndian, "dwarf: line number program header: file name directory index");
        modificationTime = readULEB128<DWARFUDWord>(src, length, littleEndian, "dwarf: line number program header: file name modification time");
        fileLength = readULEB128<DWARFUDWord>(src, length, littleEndian, "dwarf: line number program header: file name file length");
    }
}

inline void LineNumberProgramHeader::deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian)
{
    unitLength.deserialize(src, length, littleEndian);

    version = readInteger<DWARFUHalf>(src, length, littleEndian, "dwarf: line number program header: version");
    if (version < 2)
        throw std::runtime_error("dwarf: line number program header: wrong version");

    if (unitLength.is64Bit)
    {
        headerLength = readInteger<DWARFUDWord>(src, length, littleEndian, "dwarf: line number program header: 64-bit length");
    }
    else
    {
        DWARFUWord headerLength = readInteger<DWARFUWord>(src, length, littleEndian, "dwarf: line number program header: length");
        this->headerLength = headerLength;
    }

    std::size_t startLength = length;
    minimumInstructionLength = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number program header: minimum instruction length");

    if (version >= 4)
        maximumOperationsPerInstruction = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number program header: maximum operations per instruction");

    defaultIsStmt = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number program header: default is stmt");
    lineBase = readInteger<DWARFSByte>(src, length, littleEndian, "dwarf: line number program header: line base");
    lineRange = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number program header: line range");
    opcodeBase = readInteger<DWARFUByte>(src, length, littleEndian, "dwarf: line number program header: opcode base");

    if (!standardOpcodeLengths.empty())
        standardOpcodeLengths.clear();
    for (std::size_t i = 1; i < opcodeBase; ++i)
    {
        LineNumberOpcode opcode(i);
        opcode.deserialize(src, length, littleEndian);
        standardOpcodeLengths.push_back(opcode);
    }

    if (!includeDirectories.empty())
        includeDirectories.clear();
    while (true)
    {
        std::string path(reinterpret_cast<const char*>(src));
        if (path.length() + 1 > length)
            throw std::runtime_error("dwarf: line number program header: include directory");
        src += path.length() + 1;
        length -= path.length() + 1;
        if (path.empty())
            break;
        includeDirectories.push_back(path);
    }

    if (!fileNames.empty())
        fileNames.clear();
    while (true)
    {
        LineNumberFileName fileName;
        fileName.deserialize(src, length, littleEndian);
        if (fileName.filename.empty())
            break;
        fileNames.push_back(fileName);
    }

    std::size_t myheaderLength = startLength - length;
    if (myheaderLength > headerLength)
        throw std::runtime_error("dwarf: line number program header: wrong header length");
    if (myheaderLength < headerLength)
    {
       src += headerLength - myheaderLength;
       length -= headerLength -myheaderLength;
    }
}

inline std::string LineNumberRow::getSourceLine() const
{
    assert(lineNumberUnit);
    std::ostringstream strstr;
    if (file > 0)
    {
        const LineNumberFileName & filename = lineNumberUnit->header.fileNames[file - 1];
        if (filename.directoryIndex > 0)
            strstr << lineNumberUnit->header.includeDirectories[filename.directoryIndex - 1] << "/";
        strstr << filename.filename << ":";
    }
    strstr << line;
    return strstr.str();
}

inline void LineNumberUnit::deserialize(const uint8_t * & src, std::size_t & length, bool littleEndian, bool arch64Bit)
{
    std::size_t unitStart = length;

    header.deserialize(src, length, littleEndian);

    std::size_t unitLength = header.unitLength.value + (header.unitLength.is64Bit ? 12 : 4);
    if (unitLength > unitStart)
        throw std::runtime_error("dwarf: line number program: wrong initial length");
    std::size_t unitEnd = unitStart - unitLength;

    LineNumberRow lineNumberRow(this, header.defaultIsStmt);
    while (length > unitEnd)
    {
        DWARFUByte opcode = readInteger<DWARFUByte>(src , length, littleEndian, "dwarf: line number program: opcode");
        if (opcode == 0) // extended opcode
        {
            LineNumberExtendedOpcode extendedOpcode;
            extendedOpcode.deserialize(src, length, littleEndian);

            switch (extendedOpcode.code)
            {
            case LineNumberExtendedOpcode::DW_LNE_end_sequence:
                // This opcode takes no operands. It sets the end_sequence register of the state machine
                // to true and appends a row to the matrix using the current values of the state-machine
                // registers. Then it resets the registers to the initial values. Every line number
                // program sequence must end with a DW_LNE_end_sequence instruction which creates a row
                // whose address is that of the byte after the last target machine instruction of the
                // sequence.
                {
                    lineNumberRow.endSequence = true;
                    push_back(lineNumberRow);
                    lineNumberRow = LineNumberRow(this, header.defaultIsStmt);
                }
                break;
            case LineNumberExtendedOpcode::DW_LNE_set_address:
                // This opcode takes a single relocatable address as an operand. The size of the
                // operand is the size of an address on the target machine. It sets the address
                // register to the value given by the relocatable address and sets the op_index
                // register to 0.
                // All of the other line number program opcodes that affect the address register
                // add a delta to it. This instruction stores a relocatable value into it instead.
                if (arch64Bit)
                {
                    lineNumberRow.address = readInteger<DWARFUDWord>(src, length, littleEndian, "dwarf: line number program extended opcode: 64-bit address");
                }
                else
                {
                    lineNumberRow.address = readInteger<DWARFUWord>(src, length, littleEndian, "dwarf: line number program extended opcode: address");
                }
                break;
            case LineNumberExtendedOpcode::DW_LNE_define_file:
                // The DW_LNE_define_file opcode takes four operands:
                // 1. A null-terminated string containing the full or relative path name of a source
                //    file. If the entry contains a file name or a relative path name, the file is
                //    located relative to either the compilation directory (as specified by the
                //    DW_AT_comp_dir attribute given in the compilation unit) or one of the
                //    directories in the include_directories section.
                // 2. An unsigned LEB128 number representing the directory index of the directory in
                //    which the file was found.
                // 3. An unsigned LEB128 number representing the time of last modification of the
                //    file, or 0 if not available.
                // 4. An unsigned LEB128 number representing the length in bytes of the file, or 0
                //    if not available.
                // The directory index represents an entry in the include_directories section of the
                // line number program header. The index is 0 if the file was found in the current
                // directory of the compilation, 1 if it was found in the first directory in the
                // include_directories section, and so on.
                // The directory index is ignored for file names that represent full path names.
                // The primary source file is described by an entry whose path name exactly matches
                // that given in the DW_AT_name attribute in the compilation unit, and whose
                // directory index is 0.
                // The files are numbered, starting at 1, in the order in which they appear; the
                // names in the header come before names defined by the DW_LNE_define_file instruction.
                // These numbers are used in the file register of the state machine.
                {
                    LineNumberFileName fileName;
                    fileName.deserialize(src, length, littleEndian);
                    header.fileNames.push_back(fileName);
                }
                break;
            case LineNumberExtendedOpcode::DW_LNE_set_discriminator:
                // This opcode takes a single parameter, an unsigned LEB128 integer.
                // It sets the discriminator register to the new value.
                lineNumberRow.discriminator = readULEB128<DWARFUHalf>(src, length, littleEndian, "dwarf: line number program extended opcode: set discriminator");
                break;
            default:
                // unknown extended opcode
                src += extendedOpcode.length;
                length -= extendedOpcode.length;
            }
        }
        else if (opcode < header.opcodeBase) // standard opcode
        {
            switch (opcode)
            {
            case LineNumberOpcode::DW_LNS_copy:
                // This opcode takes no operands. It appends a row to the matrix using the current
                // values of the state machine registers. Then it sets the discriminator register
                // to 0, and sets the basic_block, prologue_end and epilogue_begin registers to false.
                {
                    push_back(lineNumberRow);
                    lineNumberRow.discriminator = 0;
                    lineNumberRow.basicBlock = false;
                    lineNumberRow.prologueEnd = false;
                    lineNumberRow.epilogueBegin = false;
                }
                break;
            case LineNumberOpcode::DW_LNS_advance_pc:
                // This opcode takes a single unsigned LEB128 operand as the operation advance and
                // modifies the address and op_index registers as...
                lineNumberRow.address += readULEB128<DWARFUDWord>(src, length, littleEndian, "dwarf: line number program opcode: advance pc") * header.minimumInstructionLength;
                break;
            case LineNumberOpcode::DW_LNS_advance_line:
                // The DW_LNS_advance_line opcode takes a single signed LEB128 operand and adds
                // that value to the line register of the state machine.
                lineNumberRow.line += readSLEB128<DWARFSDWord>(src, length, littleEndian, "dwarf: line number program opcode: advance line");
                break;
            case LineNumberOpcode::DW_LNS_set_file:
                // This opcode takes a single unsigned LEB128 operand and stores it in the file
                // register of the state machine.
                lineNumberRow.file = readULEB128<DWARFUWord>(src, length, littleEndian, "dwarf: line number program opcode: set file");
                break;
            case LineNumberOpcode::DW_LNS_set_column:
                // This opcode takes a single unsigned LEB128 operand and stores it in the column register
                // of the state machine.
                lineNumberRow.column = readULEB128<DWARFUWord>(src, length, littleEndian, "dwarf: line number program opcode: set column");
                break;
            case LineNumberOpcode::DW_LNS_negate_stmt:
                // This opcode takes no operands. It sets the @e isStmt register of the state machine to
                // the logical negation of its current value.
                lineNumberRow.isStmt = !lineNumberRow.isStmt;
                break;
            case LineNumberOpcode::DW_LNS_set_basic_block:
                // This opcode takes no operands. It sets the basic_block register of the state machine to “true.”
                lineNumberRow.basicBlock = true;
                break;
            case LineNumberOpcode::DW_LNS_const_add_pc:
                // This opcode takes no operands. It advances the @e address and @e opIndex registers by the
                // increments corresponding to special opcode 255.
                {
                    DWARFUByte adjustedOpcode = 255 - header.opcodeBase;
                    DWARFUByte operationAdvance = adjustedOpcode / header.lineRange;
                    lineNumberRow.address += header.minimumInstructionLength *
                                ((lineNumberRow.opIndex + operationAdvance) / header.maximumOperationsPerInstruction);
                    if (header.maximumOperationsPerInstruction > 1)
                        lineNumberRow.opIndex = (lineNumberRow.opIndex + operationAdvance) % header.maximumOperationsPerInstruction;
                }
                break;
            case LineNumberOpcode::DW_LNS_fixed_advance_pc:
                // This opcode takes a single uhalf (unencoded) operand and adds it to the address register
                // of the state machine and sets the op_index register to 0. This is the only standard opcode
                // whose operand is not a variable length number.
                // It also does not multiply the operand by the minimum_instruction_length field of the header.
                lineNumberRow.address += readInteger<DWARFUHalf>(src, length, littleEndian, "dwarf: line number program opcode: fixed advance pc");
                break;
            case LineNumberOpcode::DW_LNS_set_prologue_end:
                // This opcode takes no operands. It sets the prologue_end register to “true”.
                // When a breakpoint is set on entry to a function, it is generally desirable for execution to be
                // suspended, not on the very first instruction of the function, but rather at a point after the
                // function's frame has been set up, after any language defined local declaration processing has
                // been completed, and before execution of the first statement of the function begins.
                // Debuggers generally cannot properly determine where this point is. This command allows a
                // compiler to communicate the location(s) to use.
                // In the case of optimized code, there may be more than one such location; for example, the code
                // might test for a special case and make a fast exit prior to setting up the frame.
                // Note that the function to which the prologue end applies cannot be directly determined from the
                // line number information alone; it must be determined in combination with the subroutine
                // information entries of the compilation (including inlined subroutines).
                lineNumberRow.prologueEnd = true;
                break;
            case LineNumberOpcode::DW_LNS_set_epilogue_begin:
                // This opcode takes no operands. It sets the epilogue_begin register to “true”.
                // When a breakpoint is set on the exit of a function or execution steps over the last executable
                // statement of a function, it is generally desirable to suspend execution after completion of the
                // last statement but prior to tearing down the frame (so that local variables can still be
                // examined). Debuggers generally cannot properly determine where this point is. This command
                // allows a compiler to communicate the location(s) to use.
                // Note that the function to which the epilogue end applies cannot be directly determined from the
                // line number information alone; it must be determined in combination with the subroutine
                // information entries of the compilation (including inlined subroutines).
                // In the case of a trivial function, both prologue end and epilogue begin may occur at the same
                // address.
                lineNumberRow.epilogueBegin = true;
                break;
            case LineNumberOpcode::DW_LNS_set_isa:
                // This opcode takes a single unsigned LEB128 operand and stores that value in the isa register of
                // the state machine.
                lineNumberRow.isa = readULEB128<DWARFUHalf>(src, length, littleEndian, "dwarf: line number program opcode: set isa");
                break;
            }
        }
        else // special opcode
        {
            // These have a ubyte opcode field and no operands.
            DWARFUByte adjustedOpcode = opcode - header.opcodeBase;
            DWARFUByte operationAdvance = adjustedOpcode / header.lineRange;
            lineNumberRow.line += header.lineBase + (adjustedOpcode % header.lineRange);
            lineNumberRow.address += header.minimumInstructionLength *
                        ((lineNumberRow.opIndex + operationAdvance) / header.maximumOperationsPerInstruction);
            if (header.maximumOperationsPerInstruction > 1)
                lineNumberRow.opIndex = (lineNumberRow.opIndex + operationAdvance) % header.maximumOperationsPerInstruction;

            push_back(lineNumberRow);

            lineNumberRow.discriminator = 0;
            lineNumberRow.basicBlock = false;
            lineNumberRow.prologueEnd = false;
            lineNumberRow.epilogueBegin = false;
        }
    }
}

inline void LineNumberSection::deserialize(const uint8_t * src, std::size_t length, bool littleEndian, bool arch64Bit)
{
    while (length)
    {
        LineNumberUnit compilationUnit;
        compilationUnit.deserialize(src, length, littleEndian, arch64Bit);
        push_back(compilationUnit);
    }
    for (const LineNumberUnit & compilationUnit : *this)
        for (const LineNumberRow & lineNumberRow : compilationUnit)
            addressIndex[lineNumberRow.address] = &lineNumberRow;
}

inline void LineNumberSection::deserialize(const std::string & filename)
{
    clear();
    if (elf::ELFFile::isELF(filename))
    {
        elf::ELFFile elfFile;
        elfFile.open(filename);
        std::deque<elf::ELFSection> sections;
        elfFile.findSections(dwarf::SN_DEBUG_LINE, sections);
        for (const elf::ELFSection & section : sections)
            deserialize(section.binaryContent, section.binaryLength,
                        elfFile.header.elfEndianness == elf::ELF_DATA2LSB,
                        elfFile.header.elfClass == elf::ELF_CLASS64);
    }
    else if (macho::MachOFile::isMachO(filename))
    {
        macho::MachOFile machoFile;
        machoFile.open(filename);
        std::deque<const macho::MachOSection*> sections;
        machoFile.findSections(dwarf::SN_DEBUG_LINE_MACHO, sections);
        for (const macho::MachOSection * section : sections)
            deserialize(section->data(), section->size(),
                        machoFile.header.isLittleEndian(),
                        machoFile.header.is64Bit());
    }
}

} // namespace dwarf

inline std::ostream & operator<<(std::ostream & stream, const dwarf::InitialLength & right)
{
    return stream << "0x" << std::hex << std::setfill('0') << std::setw(right.is64Bit ? 16 : 8) << right.value;
}

inline std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberProgramHeader & right)
{
    stream << "Line table prologue:"                                                                                           << std::endl
           << "                        unit_length: " << std::dec << right.unitLength                                          << std::endl
           << "                            version: " << std::dec << right.version                                             << std::endl
           << "                      header_length: 0x" << std::hex << std::setw(8) << std::setfill('0') << right.headerLength << std::endl
           << "         minimum_instruction_length: " << std::dec << (dwarf::DWARFUHalf) right.minimumInstructionLength        << std::endl
           << " maximum_operations_per_instruction: " << std::dec << (dwarf::DWARFUHalf) right.maximumOperationsPerInstruction << std::endl
           << "                    default_is_stmt: " << std::dec << (right.defaultIsStmt ? "true" : "false")                  << std::endl
           << "                          line_base: " << std::dec << (dwarf::DWARFSHalf) right.lineBase                        << std::endl
           << "                         line_range: " << std::dec << (dwarf::DWARFUHalf) right.lineRange                       << std::endl
           << "                        opcode_base: " << std::dec << (dwarf::DWARFUHalf) right.opcodeBase                      << std::endl;
    for (const dwarf::LineNumberOpcode & opcode : right.standardOpcodeLengths)
    {
        const char * opcodeName = dwarf::LineNumberOpcode::getName(opcode.code);
        stream << "standard_opcode_lengths[";
        if (opcodeName)
            stream << opcodeName;
        else
            stream << std::dec << (dwarf::DWARFUHalf) opcode.code;
        stream << "] = " << std::dec << (dwarf::DWARFUHalf) opcode.length << std::endl;
    }

    for (std::size_t i = 0; i < right.includeDirectories.size(); ++i)
        stream << "include_directories["
               << std::dec << std::setw(3) << std::setfill(' ') << (i+1)
               << "] = '" << right.includeDirectories[i] << "'" << std::endl;

    if (!right.fileNames.empty())
    {
        stream << "                Dir  Mod Time   File Len   File Name"                   << std::endl
               << "                ---- ---------- ---------- ---------------------------" << std::endl;
        for (std::size_t i = 0; i< right.fileNames.size(); ++i)
            stream << "file_names[" << std::dec << std::setw(3) << std::setfill(' ') << (i + 1) << "]"
                   << std::dec << std::setw(5) << std::setfill(' ') << right.fileNames[i].directoryIndex
                   << " 0x" << std::hex << std::setw(8) << std::setfill('0') << right.fileNames[i].modificationTime
                   << " 0x" << std::hex << std::setw(8) << std::setfill('0') << right.fileNames[i].fileLength
                   << " " << right.fileNames[i].filename << std::endl;
    }
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberRow & right)
{
    stream << "0x" << std::hex << std::setw(16) << std::setfill('0') << right.address
           << std::dec << std::setw(7) << std::setfill(' ') << right.line
           << std::setw(7) << right.column
           << std::setw(7) << right.file
           << std::setw(4) << right.isa
           << std::setw(14) << right.discriminator
           << " "
           << (right.isStmt ? " is_stmt" : "")
           << (right.basicBlock ? " basic_block" : "")
           << (right.prologueEnd ? " prologue_end" : "")
           << (right.epilogueBegin ? " epilogue_begin" : "")
           << (right.endSequence ? " end_sequence" : "");
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberUnit & right)
{
    stream << right.header                                                               << std::endl
           << "Address            Line   Column File   ISA Discriminator  Flags"         << std::endl
           << "------------------ ------ ------ ------ --- -------------  -------------" << std::endl;
    for (const dwarf::LineNumberRow & row : right)
        stream << row << std::endl;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const dwarf::LineNumberSection & right)
{
    for (const dwarf::LineNumberUnit & compilationUnit : right)
        stream << compilationUnit << std::endl;
    for (const dwarf::LineNumberSection::AddressIndex::value_type & paddress : right.addressIndex)
        stream << *paddress.second << std::endl;
    return stream;
}

#endif // DWARF_HPP
