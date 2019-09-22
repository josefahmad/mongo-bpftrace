#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; 

static void *thread(void *t)
{
	for (;;) {
		pthread_mutex_lock(&mutex);
		usleep(1000);
		pthread_mutex_unlock(&mutex);
	}
}

int main(void)
{
	int i;

	pthread_t threads[2];
	pthread_attr_t attr;	
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_attr_init(&attr);

	pthread_create(&threads[0], &attr, thread, NULL);
	pthread_create(&threads[1], &attr, thread, NULL);

	for (i=0; i< sizeof(threads) / sizeof(pthread_t); i++) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}


