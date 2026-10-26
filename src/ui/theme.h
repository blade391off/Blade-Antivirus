#pragma once
#include <cstdint>
namespace Blade::UI
{
struct Theme
{
	uint32_t background = 0x111216FF;
	uint32_t accent = 0x32C48CFF;
	void Apply() const;
};
}