#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
//#include "CUnit/Automated.h"
//#include "CUnit/Console.h"

#include "UID_identity.h"

#include <stdio.h>  // for printf
#include <unistd.h> // unlink

/* Test Suite setup and cleanup functions: */

int init_suite(void) { puts("\n\n\n################# INIT ##########\n\n\n"); return 0; }
int clean_suite(void) { puts("\n\n\n################# DEINIT ##########\n\n\n"); return 0; }

/************* Test case functions ****************/

void test_case_sample(void)
{
   CU_ASSERT(CU_TRUE);
   CU_ASSERT_NOT_EQUAL(2, -1);
   CU_ASSERT_STRING_EQUAL("string #1", "string #1");
   CU_ASSERT_STRING_NOT_EQUAL("string #1", "string #2");

   CU_ASSERT(CU_FALSE);
   CU_ASSERT_EQUAL(2, 3);
   CU_ASSERT_STRING_NOT_EQUAL("string #1", "string #1");
   CU_ASSERT_STRING_EQUAL("string #1", "string #2");
}

void test_case_identity1(void)
{
	char *imprinting_tpub;

	unlink("identity.db");

	UID_getLocalIdentity("tprv8ZgxMBicQKsPdoj3tQG8Z2bzNsCTsk9heayJQA1pQStVx2hLEyVwx6gfHZ2p4dSzbvaEw7qrDXnX54vTVbkLghZcB24TXuj1ADXPUCvyfcy");
	imprinting_tpub = UID_getTpub();
	CU_ASSERT_STRING_EQUAL(imprinting_tpub,"tpubDBU6qWBY1xUz9vJ8Mr7fy5wjH5mD5qAMV4ZSHXGmUvjtMyX55fXaRWaQrQCawL6ALkPFdjLhPL48LKRuanDTvXHasnG7zYVE1w45s9P3sP4");

	UID_getLocalIdentity(NULL);
	imprinting_tpub = UID_getTpub();
	CU_ASSERT_STRING_EQUAL(imprinting_tpub,"tpubDBU6qWBY1xUz9vJ8Mr7fy5wjH5mD5qAMV4ZSHXGmUvjtMyX55fXaRWaQrQCawL6ALkPFdjLhPL48LKRuanDTvXHasnG7zYVE1w45s9P3sP4");

	unlink("identity.db");

	UID_getLocalIdentity(NULL);
	imprinting_tpub = UID_getTpub();
	CU_ASSERT_STRING_NOT_EQUAL(imprinting_tpub,"tpubDBU6qWBY1xUz9vJ8Mr7fy5wjH5mD5qAMV4ZSHXGmUvjtMyX55fXaRWaQrQCawL6ALkPFdjLhPL48LKRuanDTvXHasnG7zYVE1w45s9P3sP4");

	unlink("identity.db");
}

void test_case_identity2(void)
{
	unlink("identity.db");
	UID_getLocalIdentity("tprv8ZgxMBicQKsPdoj3tQG8Z2bzNsCTsk9heayJQA1pQStVx2hLEyVwx6gfHZ2p4dSzbvaEw7qrDXnX54vTVbkLghZcB24TXuj1ADXPUCvyfcy");

	{
		uint8_t sig[64] = {0};
		uint8_t hash[32] = "\x0e\x78\xb2\x90\x4c\xff\x87\x87\x30\x04\x2f\x27\xf7\x95\xdc\x85"
						   "\xa6\xa3\x31\x2b\x6d\x84\xf7\xa4\x9d\x44\xa3\xd9\x7e\xba\xa0\xe0";
		uint8_t result[64] = "\xbc\x52\xa0\xa2\x87\xdd\xa0\x3d\x21\x92\xe1\xa5\x5e\xe3\x80\x48\x14\xb2\x88\x58\xb2\x7e\x53\x7b\x71\xae\xc6\x28\x5e\xec\xb9\x55"
							 "\x68\x31\x91\x53\xe5\x72\x6f\x63\x8c\xf1\x9e\xcc\xff\xa3\x8a\xf3\x0a\x3a\x46\x4f\x14\xf9\x35\xba\xf0\xc1\xc9\x45\x98\xd7\xdf\xe0";

		UID_Bip32Path path = {0, 0, 17};
		UID_signAt(&path, hash, sig);
		CU_ASSERT(0 == memcmp(sig, result, sizeof(result)));
	}

	unlink("identity.db");
}

void test_case_identity3(void)
{
	unlink("identity.db");
	UID_getLocalIdentity("tprv8ZgxMBicQKsPdoj3tQG8Z2bzNsCTsk9heayJQA1pQStVx2hLEyVwx6gfHZ2p4dSzbvaEw7qrDXnX54vTVbkLghZcB24TXuj1ADXPUCvyfcy");

	{
		uint8_t public_key[33] = {0};
		uint8_t result[33] = "\x03\x73\xb7\x84\x15\x0c\x5a\x81\xe6\x4a"
							 "\x82\x88\x80\xa7\xbc\x5e\x50\xee\x91\xa9"
							 "\x8b\x62\xe2\xda\xfa\xd2\x70\xa1\x56\xd8"
							 "\x2e\xb3\xc0";
		UID_Bip32Path path = {1, 0, 15};
		UID_getPubkeyAt(&path, public_key);
		CU_ASSERT(0 == memcmp(public_key, result, sizeof(result)));
	}

	{
		uint8_t public_key[33] = {0};
		uint8_t result[33] = "\x03\x73\xb7\x84\x15\x0c\x5a\x81\xe6\x4a"
							 "\x82\x88\x80\xa7\xbc\x5e\x50\xee\x91\xa9"
							 "\x8b\x62\xe2\xda\xfa\xd2\x70\xa1\x56\xd8"
							 "\x2e\xb3\xc0";
		UID_Bip32Path path = {0, 1, 31};
		UID_getPubkeyAt(&path, public_key);
		CU_ASSERT(0 != memcmp(public_key, result, sizeof(result)));
	}

	{
		uint8_t public_key[33] = {0};
		uint8_t result[33] = "\x02\x81\x47\x69\x00\xc7\x3e\x10\xf7\x6a"
							 "\x0d\xba\x80\x72\xf1\xfa\x17\xb7\x23\x8c"
							 "\xc6\x6a\x5a\x9e\x84\x7a\xa5\xba\x25\x85"
							 "\x40\xab\x4c";
		UID_Bip32Path path = {0, 1, 31};
		UID_getPubkeyAt(&path, public_key);
		CU_ASSERT(0 == memcmp(public_key, result, sizeof(result)));
	}

	unlink("identity.db");
}

void test_case_identity4(void)
{
	unlink("identity.db");
	UID_getLocalIdentity("tprv8ZgxMBicQKsPdoj3tQG8Z2bzNsCTsk9heayJQA1pQStVx2hLEyVwx6gfHZ2p4dSzbvaEw7qrDXnX54vTVbkLghZcB24TXuj1ADXPUCvyfcy");

	{
		char b58addr[BTC_ADDRESS_MAX_LENGHT] = {0};
		UID_Bip32Path path = {1, 0, 7};
		UID_getAddressAt(&path, b58addr, sizeof(b58addr));
		CU_ASSERT_STRING_EQUAL(b58addr, "mmuW9AKkDwapTeAkPmqpgBPSEkMuY2pHy5");
	}

	{
		char b58addr[BTC_ADDRESS_MAX_LENGHT] = {0};
		UID_Bip32Path path = {1, 1, 7};
		UID_getAddressAt(&path, b58addr, sizeof(b58addr));
		CU_ASSERT_STRING_NOT_EQUAL(b58addr, "mmuW9AKkDwapTeAkPmqpgBPSEkMuY2pHy5");
	}

	{
		char b58addr[BTC_ADDRESS_MAX_LENGHT] = {0};
		UID_Bip32Path path = {1, 1, 7};
		UID_getAddressAt(&path, b58addr, sizeof(b58addr));
		CU_ASSERT_STRING_EQUAL(b58addr, "mkSgTpuGsFdQkm4i1rNuydB87AVY1K6CHG");
	}

	unlink("identity.db");
}
/************* Test Runner Code goes here **************/

int main ( void )
{
   CU_pSuite pSuite = NULL;

   /* initialize the CUnit test registry */
   if ( CUE_SUCCESS != CU_initialize_registry() )
      return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite( "max_test_suite", init_suite, clean_suite );
   if ( NULL == pSuite ) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if ( (NULL == CU_add_test(pSuite, "test_case_identity1", test_case_identity1)) ||
        (NULL == CU_add_test(pSuite, "test_case_identity2", test_case_identity2)) ||
        (NULL == CU_add_test(pSuite, "test_case_identity3", test_case_identity3)) ||
        (NULL == CU_add_test(pSuite, "test_case_identity4", test_case_identity4))
      )
   {
      CU_cleanup_registry();
      return CU_get_error();
   }

   // Run all tests using the basic interface
   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();
   printf("\n");
   CU_basic_show_failures(CU_get_failure_list());
   printf("\n\n");
/*
   // Run all tests using the automated interface
   CU_automated_run_tests();
   CU_list_tests_to_file();

   // Run all tests using the console interface
   CU_console_run_tests();
*/
   /* Clean up registry and return */
   CU_cleanup_registry();
   return CU_get_error();

}
