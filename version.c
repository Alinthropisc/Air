#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "version.h.in"


static char s_full_string[128];

static char s_prog_string[256];


static const AirVersion s_version = {
    .major = AIR_VERSION_MAJOR,
    .minor = AIR_VERSION_MINOR,
    .patch = AIR_VERSION_PATCH,
    .beta = AIR_VERSION_BETA,
    .rc = AIR_VERSION_RC,
    .scm = AIR_VERSION_SCM,
    .full_string = s_full_string,
};



[[maybe_unused]]
static void air_version_init(void)
{
    if (AIR_VERSION_BETA > 0) 
    {
        snprintf(s_full_string, sizeof(s_full_string),"%u.%u.%u-beta%u (%s)",AIR_VERSION_MAJOR,AIR_VERSION_MINOR,AIR_VERSION_PATCH,AIR_VERSION_BETA,AIR_VERSION_SCM);
    } 
    else if (AIR_VERSION_RC > 0) 
    {
        snprintf(s_full_string, sizeof(s_full_string),"%u.%u.%u-rc%u (%s)",AIR_VERSION_MAJOR,AIR_VERSION_MINOR,AIR_VERSION_PATCH,AIR_VERSION_RC,AIR_VERSION_SCM);
    } 
    else 
    {
        snprintf(s_full_string, sizeof(s_full_string),"%u.%u.%u (%s)",AIR_VERSION_MAJOR,AIR_VERSION_MINOR,AIR_VERSION_PATCH,AIR_VERSION_SCM);
    }
}

const AirVersion *air_version_get(void)
{
    static bool initialized = false;

    if (!initialized) 
    {
        air_version_init();
        initialized = true;
    }
    return &s_version;
}

const char *air_version_string(const char *progname)
{
    const AirVersion *v = air_version_get();
    snprintf(s_prog_string, sizeof(s_prog_string),"%s %s", progname, v->full_string);
    return s_prog_string;
}




































