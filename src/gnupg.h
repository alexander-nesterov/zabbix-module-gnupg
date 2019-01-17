#define MODULE_NAME    "gnupg.so"

int gpgme_init(const char *GPGNAME, const char *GNUPGHOME);
int gpgme_create_context(void);
int get_delta_days(time_t expires);
int gnupg_key_autodiscovery(const char *GPGNAME, const char *GNUPGHOME, int secret, char **data);
int get_gnupg_key_name(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, char **data);
int get_gnupg_key_comment(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, char **data);
int get_gnupg_key_type(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int **data);
int get_gnupg_key_expired(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int **data);
int get_gnupg_key_days_expire(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int **data);
int get_gnupg_key_disabled(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int **data);
int get_gnupg_key_revoked(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int **data);
int get_gnupg_key_invalid(const char *GPGNAME, const char *GNUPGHOME, const char *keyID, int secret, int **data);