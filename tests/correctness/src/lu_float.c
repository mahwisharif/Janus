#include "computationKernels.h"
#include "kernelConfiguration.h"
#include "minunit/minunit.h"


MU_TEST(test_computationKernelPolybenchLuFloat_assert) {
    mu_assert_double_eq(25204600.476503, poly_lu_float_result.initArraySum);
    mu_assert_double_eq(-1624395.785872, poly_lu_float_result.modifiedArraySum);
}

MU_TEST_SUITE(test_suite) {
    MU_SUITE_CONFIGURE(&computationKernelPolybenchLuFloat, NULL);
    MU_RUN_TEST(test_computationKernelPolybenchLuFloat_assert);

}

int main() {

	#ifdef LOG_RESULTS
	// Restart the file
	logFile = fopen("log.txt", "w+");
	fclose(logFile);
	#endif /* MACRO */

	MU_RUN_SUITE(test_suite);
	MU_REPORT();
	return MU_EXIT_CODE;
}