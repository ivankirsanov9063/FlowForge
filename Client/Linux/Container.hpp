// ContainerEnv.hpp — minimal, production-safe container detection (Linux)
// Стиль: Allman, 4 пробела, без using namespace std.

#pragma once

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Container
{

bool IsRunningInContainer();

}