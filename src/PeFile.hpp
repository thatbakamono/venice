#ifndef VENICE_SRC_PEFILE_HPP_
#define VENICE_SRC_PEFILE_HPP_

#include <string>
#include <windows.h>
#include <functional>

namespace venice {

struct PeExport {
  std::string function_name;

  uint64_t ordinal;
  uint64_t RVA;
};

struct PeImport {
  std::string dll_name;
  std::string function_name;

  uint64_t RVA;
  uint64_t IAT_RVA;
};

template<typename Callback>
concept ExportCallback = std::invocable<Callback, std::string&, uint64_t, uint64_t>;

template<typename Callback>
concept ImportCallback = std::invocable<Callback, std::string&, std::string&, uint64_t>;

class PeFile {
 private:
  std::string& path_;
  uint64_t image_start_{};

  HANDLE h_file_ { };
  HANDLE h_mapping_ { };

  std::vector<PeExport> exports_ { };
  std::vector<PeImport> imports_ { };

  PIMAGE_DOS_HEADER dos_header_ { };
  PIMAGE_NT_HEADERS nt_headers_ { };
  std::vector<PIMAGE_SECTION_HEADER> section_headers_ { };

  void ParseImportTable(PIMAGE_DATA_DIRECTORY data_directory) noexcept;
  void ParseExportTable(PIMAGE_DATA_DIRECTORY data_directory) noexcept;
 public:

  enum ParseStatusCode {
    OK = 0,
    PARSING_ERROR
  };
  explicit PeFile(std::string &path): path_(path), image_start_(0) { };

  PeFile(PeFile &file) = delete;

  PeFile& operator=(const PeFile& file) = delete;
  ~PeFile();
  ParseStatusCode ParseFile() noexcept;

  [[nodiscard]] PIMAGE_DOS_HEADER GetDosHeader() const noexcept;
  [[nodiscard]] PIMAGE_NT_HEADERS GetNtHeaders() const noexcept;
  [[nodiscard]] std::vector<PIMAGE_SECTION_HEADER> GetSections() const noexcept;

  [[nodiscard]] std::vector<PeExport> GetExports() const noexcept;
  [[nodiscard]] std::vector<PeImport> GetImports() const noexcept;

  [[nodiscard]] uint64_t GetFileOffsetFromRVA(uint64_t RVA) const noexcept;

  template<typename F>
  requires ExportCallback<F>
  void ForEachExport(const F& func) const noexcept {
    for (const auto& entry : exports_) {
      func(entry.function_name, entry.ordinal, entry.RVA);
    }
  };

  template<typename F>
  requires ImportCallback<F>
  void ForEachImport(const F& func) const noexcept {
    for (const auto& entry : imports_) {
      func(entry.dll_name, entry.function_name, entry.RVA);
    }
  }
};

} // venice

#endif //VENICE_SRC_PEFILE_HPP_
