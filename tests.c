#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
//#include "CUnit/Automated.h"
//#include "CUnit/Console.h"

#include "UID_identity.h"
#include "UID_bchainBTC.h"
#include "UID_message.h"
#include "UID_dispatch.h"

#include <stdio.h>  // for printf
#include <unistd.h> // unlink


/**************************** Identity test suite *******************************/

/* Test Suite setup and cleanup functions: */

int init_identity_suite(void)  { return 0; }
int clean_identity_suite(void) { return 0; }

/************* Test case functions ****************/

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

/**************************** General test suite *******************************/

/* Test Suite setup and cleanup functions: */

int init_general_suite(void)
{
	extern cache_buffer *current;
	uint8_t bit_mask1[18] = { 0x00, 0x00, 0x00, 0x80     }; // bit 31 ON

    strncpy(current->contractsCache[0].serviceUserAddress, "my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV", sizeof(BTC_Address));          // user     m/0'/0/0
    strncpy(current->contractsCache[0].serviceProviderAddress, "mw5oLLjxSNsPRdDgArCZseGEQJVdNYNK5U", sizeof(BTC_Address));      // provider m/0'/0/0
    memcpy(current->contractsCache[0].profile.bit_mask, bit_mask1, sizeof(current->contractsCache[0].profile.bit_mask));
    strncpy(current->contractsCache[1].serviceUserAddress, "myUFCeVGwkJv3PXy4zc1KSWRT8dC5iTvhU", sizeof(BTC_Address));          // user1    m/0'/0/1
    strncpy(current->contractsCache[1].serviceProviderAddress, "mtEQ22KCcjpz73hWfNvJoq6tqMEcRUKk3m", sizeof(BTC_Address));      // provider m/0'/0/1
    memset(current->contractsCache[1].profile.bit_mask, 0, sizeof(current->contractsCache[1].profile.bit_mask));
    current->validCacheEntries = 2;
    strncpy(current->clientCache[0].serviceProviderName, "LocalMachine", sizeof(((UID_ClientProfile *)0)->serviceProviderName));
    strncpy(current->clientCache[0].serviceProviderAddress, "mw5oLLjxSNsPRdDgArCZseGEQJVdNYNK5U", sizeof(((UID_ClientProfile *)0)->serviceProviderAddress));// provider m/0'/0/0
    strncpy(current->clientCache[0].serviceUserAddress, "my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV", sizeof(((UID_ClientProfile *)0)->serviceUserAddress));        // user     m/0'/0/0
    strncpy(current->clientCache[1].serviceProviderName, "UID984fee057c6d", sizeof(((UID_ClientProfile *)0)->serviceProviderName));
    strncpy(current->clientCache[1].serviceProviderAddress, "mtEQ22KCcjpz73hWfNvJoq6tqMEcRUKk3m", sizeof(((UID_ClientProfile *)0)->serviceProviderAddress));// provider m/0'/0/1
    strncpy(current->clientCache[1].serviceUserAddress, "myUFCeVGwkJv3PXy4zc1KSWRT8dC5iTvhU", sizeof(((UID_ClientProfile *)0)->serviceUserAddress));        // user1     m/0'/0/1
    strncpy(current->clientCache[2].serviceProviderName, "nocontract", sizeof(((UID_ClientProfile *)0)->serviceProviderName));
    strncpy(current->clientCache[2].serviceProviderAddress, "mtEQ22KCcjpz73hWfNvJoq6tqMEcRUKk3m", sizeof(((UID_ClientProfile *)0)->serviceProviderAddress));// provider m/0'/0/1
    strncpy(current->clientCache[2].serviceUserAddress, "n1UevZASvVyNhAB2d5Nm9EaHFeooJZbSP7", sizeof(((UID_ClientProfile *)0)->serviceUserAddress));        // user1     m/0'/0/3
    current->validClientEntries = 3;


	unlink("identity.db");
	UID_getLocalIdentity("tprv8ZgxMBicQKsPdoj3tQG8Z2bzNsCTsk9heayJQA1pQStVx2hLEyVwx6gfHZ2p4dSzbvaEw7qrDXnX54vTVbkLghZcB24TXuj1ADXPUCvyfcy");
	return 0;
}
int clean_general_suite(void)
{
	unlink("identity.db");
	return 0;
}

/************* Test case functions ****************/

void test_case_general1(void)
{
	UID_ClientChannelCtx u_ctx;

	// user
	CU_ASSERT_NOT_EQUAL(0, UID_createChannel("noName", &u_ctx));
	CU_ASSERT_EQUAL(0, UID_createChannel("LocalMachine", &u_ctx));
	CU_ASSERT_STRING_EQUAL("mw5oLLjxSNsPRdDgArCZseGEQJVdNYNK5U", u_ctx.peerid);
	CU_ASSERT_STRING_EQUAL("my3CohS9f57yCqNy4yAPbBRqLaAAJ9oqXV", u_ctx.myid);
{
	uint8_t msg[500] = {0};
	size_t size = 3;
	int64_t sID0 = 0;
	CU_ASSERT_NOT_EQUAL(0, UID_formatReqMsg(u_ctx.myid, 31, "Test ECHO", msg, &size, &sID0));
}
	uint8_t msg[500] = {0};
	size_t size = sizeof(msg);
	int64_t sID0 = 0;
	CU_ASSERT_EQUAL(0, UID_formatReqMsg(u_ctx.myid, 31, "Test ECHO", msg, &size, &sID0));
	CU_ASSERT_NOT_EQUAL(sizeof(msg), size);
	CU_ASSERT_NOT_EQUAL(0, sID0);

	// provider
	uint8_t fmsg[500] = {0};
	size_t fsize = sizeof(fmsg);
	UID_ServerChannelCtx sctx;
	UID_accept_channel(msg, size, &sctx, fmsg, &fsize);

{
	char sender[35] = {0};
	int method = 0;
	char params[100] = {0};
	int64_t sID1 = 0;
	CU_ASSERT_NOT_EQUAL(0, UID_parseReqMsg((uint8_t *)"Foo bar", fsize, sender, sizeof(sender), &method, params, sizeof(params), &sID1));
}
	char sender[35] = {0};
	int method = 0;
	char params[100] = {0};
	int64_t sID1 = 0;
	CU_ASSERT_EQUAL(0, UID_parseReqMsg(fmsg, fsize, sender, sizeof(sender), &method, params, sizeof(params), &sID1));

	CU_ASSERT_STRING_EQUAL(u_ctx.myid, sender);
	CU_ASSERT_EQUAL(31,method);
	CU_ASSERT_STRING_EQUAL("Test ECHO", params);
	CU_ASSERT_EQUAL(sID0, sID1);
	CU_ASSERT_STRING_EQUAL(sender, sctx.contract.serviceUserAddress);

	CU_ASSERT_NOT_EQUAL(0, UID_checkPermission(method, sctx.contract.profile));
	CU_ASSERT_EQUAL(0, UID_checkPermission(30, sctx.contract.profile));

	char result[100];
	CU_ASSERT_EQUAL(0, UID_performRequest(method, params, result, sizeof(result)));

	CU_ASSERT_STRING_EQUAL("UID_echo: <Test ECHO>", result);

	uint8_t response[500] = {0};
	size_t rsize = sizeof(response);
	CU_ASSERT_EQUAL(0, UID_formatRespMsg(sctx.contract.serviceProviderAddress, result, 0, sID1, response, &rsize));

	CU_ASSERT_NOT_EQUAL(sizeof(response), rsize);

	CU_ASSERT_EQUAL(0, UID_closeServerChannel(&sctx));

	//user
	char r_sender[35] = {0};
	int r_error = -1;
	char r_result[100] = {0};
	int64_t sID2 = 0;
	CU_ASSERT_EQUAL(0, UID_parseRespMsg(response, rsize, r_sender, sizeof(r_sender), &r_error, r_result, sizeof(r_result), &sID2));

	CU_ASSERT_STRING_EQUAL(u_ctx.peerid, r_sender);
	CU_ASSERT_EQUAL(0, r_error);
	CU_ASSERT_STRING_EQUAL("UID_echo: <Test ECHO>", r_result);
	CU_ASSERT_EQUAL(sID1, sID2);

	CU_ASSERT_EQUAL(0, UID_closeChannel(&u_ctx));
}


/************* Test Runner Code goes here **************/

int main ( void )
{
   CU_pSuite pSuite = NULL;

   /* initialize the CUnit test registry */
   if ( CUE_SUCCESS != CU_initialize_registry() )
      return CU_get_error();

   /* add a suite to the registry */
   pSuite = CU_add_suite( "identity test suite", init_identity_suite, clean_identity_suite );
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

   /* add a suite to the registry */
   pSuite = CU_add_suite( "general test suite", init_general_suite, clean_general_suite );
   if ( NULL == pSuite ) {
      CU_cleanup_registry();
      return CU_get_error();
   }

   /* add the tests to the suite */
   if ( (NULL == CU_add_test(pSuite, "test_case_general1", test_case_general1))
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
