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
    auto *section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(image_start_ + dos_header_->e_lfanew + sizeof(_IMAGE_NT_HEADERS64) + i * sizeof(IMAGE_SECTION_HEADER));

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
  const auto iat_rva = nt_headers_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;

  // Get the Import Descriptors
  const auto *imports = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
    image_start_ + GetFileOffsetFromRVA(data_directory->VirtualAddress)
  );

  // Iterate through the Import Descriptors
  while (imports->Name != 0) {
    // Get the DLL name
    const auto *dll_name = reinterpret_cast<const char*>(
      image_start_ + GetFileOffsetFromRVA(imports->Name)
    );

    // Get the Original First Thunk (import names) and First Thunk (IAT)
    const auto *thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(
      image_start_ + GetFileOffsetFromRVA(imports->OriginalFirstThunk)
    );
    const auto *iat_thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(
      image_start_ + GetFileOffsetFromRVA(imports->FirstThunk)
    );

    // Iterate through the functions in the DLL
    const auto first_thunk_address = reinterpret_cast<uint64_t>(thunk);
    while (thunk->u1.AddressOfData != 0) {
      const auto current_idx = reinterpret_cast<uint64_t>(thunk) - first_thunk_address;
      if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        // Import by ordinal
        imports_.push_back(PeImport{
          .dll_name = dll_name,
          .function_name = "Ordinal_" + std::to_string(IMAGE_ORDINAL(thunk->u1.Ordinal)),
          .RVA = thunk->u1.Ordinal,
          .IAT_RVA = (iat_rva + current_idx)
        });
      } else {
        // Import by name
        const auto *import_by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
          image_start_ + GetFileOffsetFromRVA(thunk->u1.AddressOfData)
        );

        imports_.push_back(PeImport{
          .dll_name = dll_name,
          .function_name = import_by_name->Name,
          .RVA = thunk->u1.AddressOfData,
          .IAT_RVA = (imports->FirstThunk + current_idx)
        });
      }

      // Move to the next function
      ++thunk;
      ++iat_thunk;
    }

    // Move to the next DLL
    ++imports;
  }
}

void PeFile::ParseExportTable(PIMAGE_DATA_DIRECTORY data_directory) noexcept {
  if (!data_directory || data_directory->VirtualAddress == 0) {
    return;
  }

  const auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      image_start_ + this->GetFileOffsetFromRVA(data_directory->VirtualAddress));

  if (!exports) {
    return;
  }

  const auto address_of_functions = reinterpret_cast<uint32_t *>(
      image_start_ + this->GetFileOffsetFromRVA(exports->AddressOfFunctions));
  const auto address_of_name_ord = reinterpret_cast<uint16_t *>(
      image_start_ + this->GetFileOffsetFromRVA(exports->AddressOfNameOrdinals));
  const auto address_of_names = reinterpret_cast<uint32_t *>(
      image_start_ + this->GetFileOffsetFromRVA(exports->AddressOfNames));

  if (!address_of_functions || !address_of_name_ord || !address_of_names) {
    return;
  }

  for (auto i = 0; i < exports->NumberOfFunctions; i++) {
    if (address_of_functions[i] == 0) {
      continue;
    }

    std::string function_name;
    const uint16_t ordinal = static_cast<uint16_t>(exports->Base + i);

    bool has_name = false;
    for (auto j = 0; j < exports->NumberOfNames; j++) {
      if (address_of_name_ord[j] == i) {
        function_name = std::string(reinterpret_cast<char *>(
            image_start_ + this->GetFileOffsetFromRVA(address_of_names[j])));
        has_name = true;
        break;
      }
    }

    if (!has_name) {
      function_name = "Ordinal_" + std::to_string(ordinal);
    }

    exports_.push_back(PeExport{
        function_name,
        static_cast<uint64_t>(ordinal),
        address_of_functions[i]});
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

uint64_t PeFile::GetFileOffsetFromRVA(uint64_t rva) const noexcept {
  // Iterate through the section headers to find the section that contains the
  // RVA
  const auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(
      image_start_ + dos_header_->e_lfanew + sizeof(IMAGE_NT_HEADERS));

  for (int i = 0; i < nt_headers_->FileHeader.NumberOfSections; ++i) {
    // Check if the RVA falls within this section's virtual address range
    if (rva >= section_header[i].VirtualAddress &&
        rva < section_header[i].VirtualAddress +
                  section_header[i].SizeOfRawData) {
      // Calculate the file offset by adding the section's pointer to raw data
      // and the difference between the RVA and the section's virtual address
      return section_header[i].PointerToRawData +
             (rva - section_header[i].VirtualAddress);
    }
  }

  // If the RVA is not found in any section, return 0 (invalid)
  return 0;
}

} // venice
