#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

//--------------------------------------------------------------------------
struct plugin_ctx_t : public plugmod_t
{
    bool idaapi run(size_t) override
    {
        msg("Hello from native!\n");
        return true;
    }
};

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL | PLUGIN_MULTI,
    []()->plugmod_t* {return new plugin_ctx_t; }, // initialize
    nullptr,
    nullptr,
    "This is an example native plugin (comment)", // long comment about the plugin
    "This is an example native plugin",           // multiline help about the plugin
    "Example native plugin",                      // the preferred short name of the plugin
    nullptr,                                      // the preferred hotkey to run the plugin
};
