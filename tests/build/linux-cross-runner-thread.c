/* Exercises target threads through the native Linux-user runner. */
#include <pthread.h>
#include <stdio.h>

static void *worker(void *argument)
{
	return argument;
}

int main(void)
{
	pthread_t thread;
	void *const expected_result = (void *)0x2a;
	void *actual_result = NULL;

	if (pthread_create(&thread, NULL, worker, expected_result) != 0)
		return 1;
	if (pthread_join(thread, &actual_result) != 0)
		return 2;
	if (actual_result != expected_result)
		return 3;

	return puts("AOS cross runner thread probe passed") < 0;
}
