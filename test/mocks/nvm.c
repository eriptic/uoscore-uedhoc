#include "oscore.h"

enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn)
{
	(void)nvm_key;
	(void)ssn;
	PRINT_MSG("NVM write mock\n");
	return ok;
}

enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn)
{
	(void)nvm_key;
	PRINT_MSG("NVM read mock\n");
	*ssn = 0;
	return ok;
}
