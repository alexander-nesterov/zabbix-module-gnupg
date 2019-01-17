#include "sysinc.h"
#include "module.h"
#include "common.h"
#include "log.h"
#include "version.h"
#include "gnupg.h"

static int item_timeout = 0;
static int zbx_module_gnupg_key_autodiscovery(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_name(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_comment(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_type(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_expired(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_days_expire(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_disabled(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_revoked(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbx_module_gnupg_key_invalid(AGENT_REQUEST *request, AGENT_RESULT *result);

static ZBX_METRIC keys[] =
/*            KEY                    FLAG                   FUNCTION       TEST PARAMETERS */
{
    {"gnupg.key.autodiscovery", CF_HAVEPARAMS, zbx_module_gnupg_key_autodiscovery, NULL},
    {"gnupg.key.name",          CF_HAVEPARAMS, zbx_module_gnupg_key_name,          NULL},
    {"gnupg.key.comment",       CF_HAVEPARAMS, zbx_module_gnupg_key_comment,       NULL},
    {"gnupg.key.type",          CF_HAVEPARAMS, zbx_module_gnupg_key_type,          NULL},
    {"gnupg.key.expired",       CF_HAVEPARAMS, zbx_module_gnupg_key_expired,       NULL},
    {"gnupg.key.days.expire",   CF_HAVEPARAMS, zbx_module_gnupg_key_days_expire,   NULL},
    {"gnupg.key.disabled",      CF_HAVEPARAMS, zbx_module_gnupg_key_disabled,      NULL},
    {"gnupg.key.revoked",       CF_HAVEPARAMS, zbx_module_gnupg_key_revoked,       NULL},
    {"gnupg.key.invalid",       CF_HAVEPARAMS, zbx_module_gnupg_key_invalid,       NULL},
    {NULL}
};

/******************************************************************************
*                                                                            *
* Function: zbx_module_api_version                                           *
*                                                                            *
* Purpose: returns version number of the module interface                    *
*                                                                            *
* Return value: ZBX_MODULE_API_VERSION - version of module.h module is       *
*               compiled with, in order to load module successfully Zabbix   *
*               MUST be compiled with the same version of this header file   *
*                                                                            *
******************************************************************************/
int zbx_module_api_version(void)
{
    return ZBX_MODULE_API_VERSION;
}

/******************************************************************************
*                                                                            *
* Function: zbx_module_init                                                  *	
*                                                                            *	
* Purpose: the function is called on agent startup                           *	
*          It should be used to call any initialization routines             *	
*                                                                            *	
* Return value: ZBX_MODULE_OK - success                                      *	
*               ZBX_MODULE_FAIL - module initialization failed               *	
*                                                                            *	
* Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
*                                                                            *	
******************************************************************************/
int zbx_module_init(void)
{
    srand(time(NULL));

    zabbix_log(LOG_LEVEL_INFORMATION, 
               "Module: %s - build with agent: %d.%d.%d; OS: %s; Release: %s; Hostname: %s (%s:%d)",
               MODULE_NAME, ZABBIX_VERSION_MAJOR, ZABBIX_VERSION_MINOR, ZABBIX_VERSION_PATCH, 
               "", "", "",
               __FILE__, __LINE__);

    return ZBX_MODULE_OK;
}

/******************************************************************************
*                                                                            *
* Function: zbx_module_uninit                                                *
*                                                                            *
* Purpose: the function is called on agent shutdown                          *
*          It should be used to cleanup used resources if there are any      *
*                                                                            *
* Return value: ZBX_MODULE_OK - success                                      *
*               ZBX_MODULE_FAIL - function failed                            *
*                                                                            *
******************************************************************************/
int zbx_module_uninit(void)
{
    return ZBX_MODULE_OK;
}

/******************************************************************************
*                                                                            *
* Function: zbx_module_item_list                                             *
*                                                                            *
* Purpose: returns list of item keys supported by the module                 *
*                                                                            *
* Return value: list of item keys                                            *
*                                                                            *
******************************************************************************/
ZBX_METRIC *zbx_module_item_list()
{
    return keys;
}

/******************************************************************************
*                                                                            *
* Function: zbx_module_item_timeout                                          *
*                                                                            *
* Purpose: set timeout value for processing of items                         *
*                                                                            *
* Parameters: timeout - timeout in seconds, 0 - no timeout set               *
*                                                                            *
******************************************************************************/
void zbx_module_item_timeout(int timeout)
{
    item_timeout = timeout;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_autodiscovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_autodiscovery";
    const char *GPGNAME;
    const char *GNUPGHOME;
    int secret;
    char *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG, 
               "Module: %s - param num: %d (%s:%d)",
               MODULE_NAME, request->nparam, __FILE__, __LINE__);

    if (3 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    secret = atoi(get_rparam(request, 2));

    ret = gnupg_key_autodiscovery(GPGNAME, GNUPGHOME, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("Autodiscovery failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - raw data: %s (%s:%d)",
               MODULE_NAME, __function_name, data, __FILE__, __LINE__);

    SET_STR_RESULT(result, zbx_strdup(NULL, data));
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_name(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_name";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    char *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_name(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_name failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_STR_RESULT(result, zbx_strdup(NULL, data));
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_comment(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_comment";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    char *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_comment(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_comment failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_STR_RESULT(result, zbx_strdup(NULL, data));
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_type(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_type";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    int *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_type(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_type failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_UI64_RESULT(result, data);
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_expired(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_expired";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    int *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_expired(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_expired failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_UI64_RESULT(result, data);
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_days_expire(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_days_expire";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    int *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_expired(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_days_expire failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_UI64_RESULT(result, data);
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_disabled(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_disabled";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    int *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_disabled(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_disabled failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_UI64_RESULT(result, data);
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_revoked(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_revoked";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    int *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_revoked(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_revoked failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_UI64_RESULT(result, data);
    data = NULL;
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
static int zbx_module_gnupg_key_invalid(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char *__function_name = "zbx_module_gnupg_key_invalid";
    const char *GPGNAME;
    const char *GNUPGHOME;
    const char *keyID;
    int secret;
    int *data = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_DEBUG,
               "Module: %s, function: %s - param num: %d (%s:%d)",
               MODULE_NAME, __function_name, request->nparam, __FILE__, __LINE__);

    if (4 != request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters, see log"));

        zabbix_log(LOG_LEVEL_DEBUG, "Module: %s, function: %s - invalid number of parameters (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    GPGNAME = get_rparam(request, 0);
    GNUPGHOME = get_rparam(request, 1);
    keyID = get_rparam(request, 2);
    secret = atoi(get_rparam(request, 3));

    ret = get_gnupg_key_invalid(GPGNAME, GNUPGHOME, keyID, secret, &data);
    if (ret != SYSINFO_RET_OK)
    {
        SET_MSG_RESULT(result, strdup("zbx_module_gnupg_key_invalid failed, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - module failed (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    if (data == NULL)
    {
        SET_MSG_RESULT(result, strdup("Data is NULL, see log"));
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - data is NULL (%s:%d)",
                  MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    SET_UI64_RESULT(result, data);
    data = NULL;
    return SYSINFO_RET_OK;
}