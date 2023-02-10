#include <encryption.h>
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

const char sign[] = "$^&#@*(Q%LKZENC#%*&#WQ%^&";
const size_t sign_size = sizeof(sign) - 1;
const size_t readblk = 64;

union _dmb {
	uint16_t siz;
	char dat[2];
};

int main(int argc, char* argv[])
{
	std::cout << "Hello, do you want to [E]ncrypt or [D]ecrypt a file?" << std::endl;
	std::cout << "Note: final file will always be 'enc.txt' for encrypt and 'dec.txt' for decrypt. Extension is not saved!" << std::endl;

	std::string opt;
	std::getline(std::cin, opt);

	const bool is_enc = (opt == "E");

	std::string filenam;
	if (argc == 2) {
		filenam = argv[1];
		std::cout << "Working with file dragged into the app: '" << filenam << "'..." << std::endl;
	}
	else {
		std::cout << "What file to encrypy/decrypt? ";
		std::cin >> filenam;
		std::cout << "Working with file: '" << filenam << "'..." << std::endl;
	}

	std::fstream f(filenam.c_str(), std::ios::in | std::ios::binary);
	std::fstream o(is_enc ? "enc.txt" : "dec.txt", std::ios::out | std::ios::binary);

	if (!f || f.bad()) {
		std::cout << "Cannot open INPUT file. FAILED." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(10));
		return 1;
	}
	if (!o || o.bad()) {
		std::cout << "Cannot open OUTPUT file. FAILED." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(10));
		return 1;
	}

	if (is_enc) {
		auto enc = Lunaris::make_encrypt_auto();		
		auto keys = enc.get_combo();
		
		o.write(sign, sign_size);
		o.write((char*)&keys, sizeof(keys));

		//std::cout << "Sorted random keyset: " << keys.key << "; " << keys.mod << std::endl;

		{
			uint8_t buf[readblk]{};

			while (f && f.good() && !f.eof()) {
				f.read((char*)buf, readblk);
				const size_t rread = f.gcount();
				if (rread == 0) break;
				
				std::vector<uint8_t> _fin;

				if (!enc.transform(buf, rread, _fin)) {
					std::cout << "Cannot encode stuff. Something really weird happened. Sorry." << std::endl;
					std::this_thread::sleep_for(std::chrono::seconds(10));
					return 3;
				}

				_dmb dmb{};
				dmb.siz = static_cast<uint16_t>(_fin.size());

				o.write(dmb.dat, sizeof(dmb.dat));
				o.write((char*)_fin.data(), _fin.size());
			}
		}
	}
	else {
		decltype(Lunaris::make_encrypt_auto().get_combo()) keys{};
		char minbuf[sign_size + sizeof(keys)];

		f.read(minbuf, sizeof(minbuf));
		if (f.gcount() != sizeof(minbuf) || strncmp(minbuf, sign, sign_size) != 0) {
			std::cout << "Could not read signature. Failed." << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(10));
			return 2;
		}

		memcpy_s(&keys, sizeof(keys), minbuf + sign_size, sizeof(keys));

		auto dec = Lunaris::make_decrypt_auto(keys);

		//std::cout << "Sorted random keyset: " << dec.get_key() << "; " << dec.get_mod() << std::endl;

		{
			while (f && f.good() && !f.eof()) {
				_dmb dmb{};

				f.read(dmb.dat, sizeof(dmb.dat));

				if (f.eof()) break;

				if (f.gcount() != sizeof(dmb.dat)) {
					std::cout << "Cannot decode stuff. Something really weird happened (size alloc fail). Sorry." << std::endl;
					std::this_thread::sleep_for(std::chrono::seconds(10));
					return 3;
				}

				std::vector<uint8_t> buf(dmb.siz, 0);

				f.read((char*)buf.data(), static_cast<size_t>(dmb.siz));
				const size_t rread = f.gcount();

				if (rread == 0) break;
				if (rread != static_cast<size_t>(dmb.siz)) {
					std::cout << "Read mismatch " << rread << " != " << dmb.siz << ". Failed." << std::endl;
					std::this_thread::sleep_for(std::chrono::seconds(10));
					return 3;
				}

				std::vector<uint8_t> _fin;

				if (!dec.transform(buf.data(), buf.size(), _fin)) {
					std::cout << "Cannot decode stuff. Something really weird happened. Sorry." << std::endl;
					std::this_thread::sleep_for(std::chrono::seconds(10));
					return 3;
				}

				o.write((char*)_fin.data(), _fin.size());
			}
		}
	}

	std::cout << "Flushing stuff..." << std::endl;

	f.flush();
	o.flush();

	f.close();
	o.close();

	std::cout << "Hopefully this is the end! Have fun!" << std::endl;
	std::this_thread::sleep_for(std::chrono::seconds(10));
	return 0;
}