#include <iostream>
#include "reflective_loader.h"

#include <string>

int main(int argc, char* argv[]) {
	if (argc != 2) std::cout << "Usage: " << argv[0] << " [PATH_TO_PE]" << std::endl;
	else {
		ReflectiveLoader loader;
		if (loader.load_PE(argv[1])) {
			loader.execute_PE();
		}
	}
	return 0;
}