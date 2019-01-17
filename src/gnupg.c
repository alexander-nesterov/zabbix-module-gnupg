#include "sysinc.h"
#include "module.h"
#include "common.h"
#include "log.h"
#include "zbxjson.h"
#include <locale.h>
#include "gnupg.h"
#include "gpgme.h"

gpgme_ctx_t ctx = NULL;

/******************************************************************************
******************************************************************************/
int gpgme_init(const char *GPGNAME, const char *GNUPGHOME)
{
    const char *__function_name = "gpgme_init";
    int ret;
    gpgme_error_t err;

    ret = setenv("GNUPGHOME", GNUPGHOME, 0);
    if (ret != 0)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                   "Module: %s, function: %s - can not set GNUPGHOME (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    /* Set the default name for the gpg binary */
    err = gpgme_set_global_flag("gpg-name", GPGNAME);
    if (err)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                   "Module: %s, function: %s - can not set the default name for the gpg binary: %s (%s:%d)",
                   MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
#ifdef LC_MESSAGES
    gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif
    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - SUCCESS (%s:%d)",
               MODULE_NAME, __function_name, __FILE__, __LINE__);
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int gpgme_create_context(void)
{
    const char *__function_name = "gpgme_create_context";
    gpgme_error_t err;

    if (!getenv("GNUPGHOME"))
    {
        zabbix_log(LOG_LEVEL_TRACE,
                   "Module: %s, function: %s - you need to set the environment variable GNUPGHOME (%s:%d)",
                   MODULE_NAME, __function_name, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    else
    {
        zabbix_log(LOG_LEVEL_TRACE,
                   "Module: %s, function: %s - environment variable GNUPGHOME: %s (%s:%d)",
                   MODULE_NAME, __function_name, getenv("GNUPGHOME"), __FILE__, __LINE__);
    }

    err = gpgme_new(&ctx);
    if (err)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                   "Module: %s, function: %s - creating GNUPGME context failed: %s (%s:%d)",
                   MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - SUCCESS (%s:%d)",
               MODULE_NAME, __function_name, __FILE__, __LINE__);
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_delta_days(time_t expires)
{
    unsigned long current_date;
    int delta;

    current_date = (unsigned long)time(NULL);
    printf("    Current unixtime: %lu\n", current_date);
    delta = (expires - current_date)/60/60/24;
    return delta;
}

/******************************************************************************
******************************************************************************/
int gnupg_key_autodiscovery(const char *GPGNAME, const char *GNUPGHOME, int secret, char **data)
{
    const char *__function_name = "gnupg_autodiscovery";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    struct zbx_json json;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - GPGNAME: %s; GNUPGHOME: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, GPGNAME, GNUPGHOME, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    zbx_json_init(&json, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&json, ZBX_PROTO_TAG_DATA);

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        zbx_json_addobject(&json, NULL);
        zbx_json_addstring(&json, "{#KEYID}", key->subkeys->keyid, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&json);
        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not list keys: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);

        return SYSINFO_RET_FAIL;
    }

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - raw data: %s (%s:%d)",
               MODULE_NAME, __function_name, json.buffer, __FILE__, __LINE__);

    *data = json.buffer;
    zbx_json_free(&json);
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_name(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, char** data)
{
    const char *__function_name = "get_gnupg_key_name";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->uids->name;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get name of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_comment(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, char** data)
{
    const char *__function_name = "get_gnupg_key_comment";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->uids->comment;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get comment of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_type(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int** data)
{
    const char *__function_name = "get_gnupg_key_type";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->subkeys->secret;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get type of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_expired(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int** data)
{
    const char *__function_name = "get_gnupg_key_expired";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->subkeys->expired;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get expired of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_days_expire(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int** data)
{
    const char *__function_name = "get_gnupg_key_days_expire";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->subkeys->expired;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get days of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_disabled(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int** data)
{
    const char *__function_name = "get_gnupg_key_disabled";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->subkeys->disabled;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get disabled of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_revoked(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int** data)
{
    const char *__function_name = "get_gnupg_key_revoked";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->subkeys->revoked;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get revoked of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_gnupg_key_invalid(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int** data)
{
    const char *__function_name = "get_gnupg_key_invalid";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    int ret;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    /* Initialize */
    ret = gpgme_init(GPGNAME, GNUPGHOME);
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    /* Create context */
    ret = gpgme_create_context();
    if (ret != SYSINFO_RET_OK)
        return SYSINFO_RET_FAIL;

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            *data = key->subkeys->invalid;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }
    gpgme_release(ctx);

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        zabbix_log(LOG_LEVEL_TRACE,
                  "Module: %s, function: %s - can not get invalid of key: %s (%s:%d)",
                  MODULE_NAME, __function_name, gpgme_strerror(err), __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    return SYSINFO_RET_OK;
}

/******************************************************************************
******************************************************************************/
int get_expires_date(const char *keyID, int secret)
{
    /*
    const char *__function_name = "get_expires_date";
    gpgme_error_t err;
    gpgme_key_t key;
    const char *pattern = NULL;
    long int date;

    zabbix_log(LOG_LEVEL_TRACE,
               "Module: %s, function: %s - keyID: %s; secret: %d (%s:%d)",
               MODULE_NAME, __function_name, keyID, secret, __FILE__, __LINE__);

    err = gpgme_op_keylist_start(ctx, pattern, secret);
    while (!err)
    {
        err = gpgme_op_keylist_next(ctx, &key);
        if (err)
            break;

        if (strcmp(key->subkeys->keyid, keyID) == 0)
        {
            date = key->subkeys->expires;
        }

        putchar ('\n');
        gpgme_key_release(key);
    }

    if (gpg_err_code(err) != GPG_ERR_EOF)
    {
        fprintf(stderr, "%s: can not list keys: %s\n",
                gpgme_strsource(err), gpgme_strerror(err));
        return SYSINFO_RET_FAIL;
    }
    */
    return SYSINFO_RET_OK;
}