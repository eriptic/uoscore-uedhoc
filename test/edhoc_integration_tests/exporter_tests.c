#include <edhoc.h>
#include <zephyr/ztest.h>
#include "edhoc_test_vectors_exporter_v15.h"

void test_exporter(void)
{
	enum err err;
	uint8_t prk_exporter[32];
	uint8_t master_secret[16];
	uint8_t master_salt[8];
	uint8_t prk_out_new[32];

	err = prk_out_update(SHA_256, T1_PRK_OUT, sizeof(T1_PRK_OUT),
			     T1_KEY_UPDATE_CONTEXT,
			     sizeof(T1_KEY_UPDATE_CONTEXT), prk_out_new);
	zassert_true(err == 0, "prk_out_update failed");
	zassert_mem_equal__(T1_PRK_OUT_NEW, prk_out_new, sizeof(prk_out_new),
			    "wrong prk_out_new");
	/***/
	/***/
	err = prk_out2exporter(SHA_256, T1_PRK_OUT, sizeof(T1_PRK_OUT),
			       prk_exporter);
	zassert_true(err == 0, "prk_out2exporter failed");
	zassert_mem_equal__(T1_PRK_EXPORTER, prk_exporter, sizeof(prk_exporter),
			    "wrong prk_exporter");
	/***/
	/***/
	err = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, prk_exporter,
			     sizeof(prk_exporter), master_secret,
			     sizeof(master_secret));
	zassert_true(err == 0, "edhoc_exporter failed");
	zassert_mem_equal__(T1_OSCORE_MASTER_SECRET, master_secret,
			    sizeof(master_secret), "wrong master_secret");
	/***/
	/***/
	err = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, prk_exporter,
			     sizeof(prk_exporter), master_salt,
			     sizeof(master_salt));
	zassert_true(err == 0, "edhoc_exporter failed");
	zassert_mem_equal__(T1_OSCORE_MASTER_SALT, master_salt,
			    sizeof(master_salt), "wrong master_salt");
}