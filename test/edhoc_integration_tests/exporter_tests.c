#include <edhoc.h>
#include <zephyr/ztest.h>
#include <zephyr/debug/thread_analyzer.h>
#include "edhoc_test_vectors_exporter_v15.h"

void test_exporter(void)
{
	enum err err;

	uint8_t prk_exporter_buf[32];
	struct byte_array prk_exporter = { .ptr = prk_exporter_buf,
					   .len = sizeof(prk_exporter_buf) };

	uint8_t prk_out_new_buf[32];
	struct byte_array prk_out_new = { .ptr = prk_out_new_buf,
					  .len = sizeof(prk_out_new_buf) };

	uint8_t master_secret_buf[16];
	struct byte_array master_secret = { .ptr = master_secret_buf,
					    .len = sizeof(master_secret_buf) };

	uint8_t master_salt_buf[8];
	struct byte_array master_salt = { .ptr = master_salt_buf,
					  .len = sizeof(master_salt_buf) };

	struct byte_array prk_out = { .ptr = T1_PRK_OUT,
				      .len = sizeof(T1_PRK_OUT) };
	struct byte_array context = { .ptr = T1_KEY_UPDATE_CONTEXT,
				      .len = sizeof(T1_KEY_UPDATE_CONTEXT) };
	/***/
	/***/
	err = prk_out_update(SHA_256, &prk_out, &context, &prk_out_new);

	zassert_true(err == 0, "prk_out_update failed");
	zassert_mem_equal__(T1_PRK_OUT_NEW, prk_out_new.ptr, prk_out_new.len,
			    "wrong prk_out_new");
	/***/
	/***/
	err = prk_out2exporter(SHA_256, &prk_out, &prk_exporter);

	zassert_true(err == 0, "prk_out2exporter failed");
	zassert_mem_equal__(T1_PRK_EXPORTER, prk_exporter.ptr, prk_exporter.len,
			    "wrong prk_exporter");
	/***/
	/***/
	err = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
			     &master_secret);
	zassert_true(err == 0, "edhoc_exporter failed");
	zassert_mem_equal__(T1_OSCORE_MASTER_SECRET, master_secret.ptr,
			    master_secret.len, "wrong master_secret");
	/***/
	/***/
	err = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
			     &master_salt);
	zassert_true(err == 0, "edhoc_exporter failed");
	zassert_mem_equal__(T1_OSCORE_MASTER_SALT, master_salt.ptr,
			    master_salt.len, "wrong master_salt");

#ifdef REPORT_STACK_USAGE
	thread_analyzer_print();
#endif
}
