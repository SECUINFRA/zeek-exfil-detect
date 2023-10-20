
#include "Plugin.h"

namespace plugin { namespace Exfiltration_exfil_detect { Plugin plugin; } }

using namespace plugin::Exfiltration_exfil_detect;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Exfiltration::exfil_detect";
	config.description = "This plugin provides various functions to enable efficient calculations of different mathematical \
						  functions. The goal is the calculation of metrics over a historical baseline with different values. \
						  Furthermore the plugin contains several helper functions for an easy implementation of the required \
						  logic.";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
