#include "PeFile.hpp"
#include <windows.h>

namespace venice {

PeFile::ParseStatusCode PeFile::ParseFile() noexcept {

  h_file_ = CreateFileA(path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h_file_ == INVALID_HANDLE_VALUE) {
    return PeFile::PARSING_ERROR;
  }

  h_mapping_ = CreateFileMappingA(h_file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (h_mapping_ == NULL) {
    return PeFile::PARSING_ERROR;
  }

  image_start_ = reinterpret_cast<uint64_t>(MapViewOfFile(h_mapping_, FILE_MAP_READ, 0, 0, 0));
  if (image_start_ == NULL) {
    return PeFile::PARSING_ERROR;
  }

  if (*reinterpret_cast<uint16_t*>(image_start_) != 0x5A4D) {
    // File does not have 'MZ' signature and is not correct PE file.

    return PeFile::PARSING_ERROR;
  }

  dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(image_start_);
  nt_headers_ = reinterpret_cast<PIMAGE_NT_HEADERS>(image_start_ + dos_header_->e_lfanew);

  for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
    IMAGE_DATA_DIRECTORY data_directory = nt_headers_->OptionalHeader.DataDirectory[i];

    if (data_directory.Size == 0) {
      continue;
    }
    
    switch (i) {
      case IMAGE_DIRECTORY_ENTRY_EXPORT: { this->ParseExportTable(&data_directory); break; }
      case IMAGE_DIRECTORY_ENTRY_IMPORT: { this->ParseImportTable(&data_directory); break; }
      default: continue;
    }
  }

  for (int i = 0; i < nt_headers_->FileHeader.NumberOfSections; i++) {
    auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(image_start_ + dos_header_->e_lfanew + sizeof(_IMAGE_NT_HEADERS64) + i * sizeof(IMAGE_SECTION_HEADER));

    section_headers_.push_back(section_header);
  }


  return PeFile::OK;
}

PeFile::~PeFile() {
  UnmapViewOfFile(reinterpret_cast<LPCVOID>(image_start_));
  CloseHandle(h_mapping_);
  CloseHandle(h_file_);
}

void PeFile::ParseImportTable(PIMAGE_DATA_DIRECTORY data_directory) noexcept {
  auto imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
      image_start_ + this->GetFileOffsetFromRVA(data_directory->VirtualAddress)
  );

  while (imports->Name != 0) {
    auto dll_name = reinterpret_cast<char *>(image_start_ + this->GetFileOffsetFromRVA(imports->Name));
    auto thunk = static_cast<int64_t>(image_start_ + this->GetFileOffsetFromRVA(imports->OriginalFirstThunk));
    // @TODO: Add IAT parsing and saving RVA for PE loading libraries

    std::string dll = std::string(dll_name);

    while (true) {
      auto rva = *reinterpret_cast<int64_t *>(thunk);

      if (rva == 0) {
        break;
      }

      if (rva > 0) {
        // import by name

        std::string function_name = std::string(reinterpret_cast<char *>(image_start_ + this->GetFileOffsetFromRVA(rva) + 2));

        imports_.push_back(PeImport {
            dll,
            function_name,
            static_cast<uint64_t>(rva)
        });
      } else {
        // import by ordinal

        std::string function_name = std::to_string(rva);

        imports_.push_back(PeImport {
            dll,
            function_name,
            static_cast<uint64_t>(rva)
        });
      }

      thunk += 8;
    }
    imports++;
  }
}

void PeFile::ParseExportTable(PIMAGE_DATA_DIRECTORY data_directory) noexcept {
  auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(image_start_ + this->GetFileOffsetFromRVA(data_directory->VirtualAddress));

  auto address_of_functions = reinterpret_cast<uint32_t *>(image_start_ + this->GetFileOffsetFromRVA(exports->AddressOfFunctions));
  auto address_of_name_ord = reinterpret_cast<uint16_t *>(image_start_ + this->GetFileOffsetFromRVA(exports->AddressOfNameOrdinals));
  auto address_of_names = reinterpret_cast<uint32_t *>(image_start_ + this->GetFileOffsetFromRVA(exports->AddressOfNames));

  for (auto i = 0; i < exports->NumberOfFunctions; i++) {
    if (address_of_functions[i] == 0) {
      continue;
    }

    std::string function_name;

    for (auto j = 0; j < exports->NumberOfNames; j++) {
      if (address_of_name_ord[j] == i) {
        function_name = std::string(reinterpret_cast<char *>(image_start_ + this->GetFileOffsetFromRVA(address_of_names[j])));
        break;
      }
    }

    exports_.push_back(PeExport {
      function_name,
      static_cast<uint64_t>(i),
      address_of_functions[i]
    });
  }
}

PIMAGE_DOS_HEADER PeFile::GetDosHeader() const noexcept {
  return dos_header_;
}

PIMAGE_NT_HEADERS PeFile::GetNtHeaders() const noexcept {
  return nt_headers_;
}

std::vector<PIMAGE_SECTION_HEADER> PeFile::GetSections() const noexcept {
  return section_headers_;
}

std::vector<PeExport> PeFile::GetExports() const noexcept {
  return exports_;
}

std::vector<PeImport> PeFile::GetImports() const noexcept {
  return imports_;
}

uint64_t PeFile::GetFileOffsetFromRVA(uint64_t RVA) const noexcept {
  uint64_t file_offset = RVA;

  for (int i = 0; i < nt_headers_->FileHeader.NumberOfSections; i++) {
    auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(image_start_ + dos_header_->e_lfanew + sizeof(_IMAGE_NT_HEADERS64) + i * sizeof(IMAGE_SECTION_HEADER));

    if (RVA > section_header->VirtualAddress && RVA < (section_header->VirtualAddress + section_header->Misc.VirtualSize)) {
      file_offset -= section_header->VirtualAddress;
      file_offset += section_header->PointerToRawData;

      break;
    }
  }

  return file_offset;
}

} // venice
