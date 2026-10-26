#include "app.h"
#include "../ui/theme.h"
#include "../scanner/scanner.h"
#include <iostream>

namespace Blade
{
int App::Run()
{
	Scanner scanner;
	scanner.initialize("");
	std::cout << "BladeAntivirus scaffold running\n";
	return 0;
}
}