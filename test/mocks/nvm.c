#include "oscore.h"

enum err nvm_write_ssn(const struct byte_array *sender_id,
			    const struct byte_array *id_context, uint64_t ssn)
{
    (void)sender_id;
    (void)id_context;
    (void)ssn;
    PRINTF("NVM write mock\n");
    return ok;
}

enum err nvm_read_ssn(const struct byte_array *sender_id,
			   const struct byte_array *id_context, uint64_t *ssn)
{
    (void)sender_id;
    (void)id_context;
    PRINTF("NVM read mock\n");
    *ssn = 0;
    return ok;
}
