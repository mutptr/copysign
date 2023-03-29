#include <Windows.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>

#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp.lib")

bool x64(IMAGE_NT_HEADERS* nt_headers)
{
	return nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

IMAGE_DATA_DIRECTORY security(IMAGE_DOS_HEADER* dos_header)
{
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((char*)dos_header + dos_header->e_lfanew);
	if (x64(nt_headers))
		return ((IMAGE_OPTIONAL_HEADER64*)&nt_headers->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	else
		return ((IMAGE_OPTIONAL_HEADER32*)&nt_headers->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
}

void security(IMAGE_DOS_HEADER* dos_header, const IMAGE_DATA_DIRECTORY& security)
{
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((char*)dos_header + dos_header->e_lfanew);
	if (x64(nt_headers))
		((IMAGE_OPTIONAL_HEADER64*)&nt_headers->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = security;
	else
		((IMAGE_OPTIONAL_HEADER32*)&nt_headers->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = security;
}

void CheckSum(IMAGE_DOS_HEADER* dos_header, DWORD checksum)
{
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((char*)dos_header + dos_header->e_lfanew);
	if (x64(nt_headers))
		((IMAGE_OPTIONAL_HEADER64*)&nt_headers->OptionalHeader)->CheckSum = checksum;
	else
		((IMAGE_OPTIONAL_HEADER32*)&nt_headers->OptionalHeader)->CheckSum = checksum;
}

int wmain(int argc, wchar_t** argv)
{
	std::wstring sign_filename;
	std::wstring target_filename;

	if (argc < 3)
	{
		std::wcout << L"Signed file: ";
		std::wcin >> sign_filename;
		std::wcout << L"Target: ";
		std::wcin >> target_filename;
	}
	else
	{
		sign_filename = argv[1];
		target_filename = argv[2];
	}

	std::ifstream sign_file{ sign_filename, std::ios::binary };
	if (!sign_file.is_open())
	{
		std::wcout << L"Open Error (" << sign_filename << L")" << std::endl;
		_wsystem(L"pause");
		return 0;
	}

	std::vector<char> sign_file_buffer;
	sign_file_buffer.resize((size_t)std::filesystem::file_size(sign_filename));

	sign_file.read(sign_file_buffer.data(), sign_file_buffer.size());
	sign_file.close();

	IMAGE_DATA_DIRECTORY security_data = security((IMAGE_DOS_HEADER*)sign_file_buffer.data());

	std::vector<char> sign_data;
	sign_data.insert(sign_data.end(), sign_file_buffer.begin() + security_data.VirtualAddress, sign_file_buffer.end());

	std::ifstream target_file{ target_filename, std::ios::binary };
	if (!target_file.is_open())
	{
		std::wcout << L"Open Error (" << target_filename << L")" << std::endl;
		_wsystem(L"pause");
		return 0;
	}

	std::vector<char> target_file_buffer;
	target_file_buffer.resize((size_t)std::filesystem::file_size(target_filename));
	size_t offset = target_file_buffer.size();

	target_file.read(target_file_buffer.data(), target_file_buffer.size());
	target_file_buffer.insert(target_file_buffer.end(), sign_data.begin(), sign_data.end());
	target_file.close();

	security_data.VirtualAddress = (DWORD)offset;
	security((IMAGE_DOS_HEADER*)target_file_buffer.data(), security_data);

	DWORD headersum = 0, checksum = 0;
	CheckSumMappedFile(target_file_buffer.data(), (DWORD)target_file_buffer.size(), &headersum, &checksum);
	CheckSum((IMAGE_DOS_HEADER*)target_file_buffer.data(), checksum);

	std::ofstream new_file{ target_filename, std::ios::binary };
	new_file.write(target_file_buffer.data(), target_file_buffer.size());
	new_file.close();
}