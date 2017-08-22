#include <stdio.h>
#include <pcap.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int o_interval_ms = 1000;
static int o_dump_stats = 1;

struct statistic {
	int bytes;
};

struct statistic stats;

static void dump_statistic(struct statistic *stats)
{
	printf("%.2f Mbit/sec\n", (double)(stats->bytes * 8/(1024*1024))/(double)(o_interval_ms/1000));
}

static int dump_statistic_to_file(char *filename_stats, struct statistic *s)
{
	char filename[] = "/tmp/mytemp.XXXXXX";
	int fd = mkstemp(filename);
	char buf[1024];

	if (fd == -1) return 1;

	sprintf(buf, "%.2f\n",  (double)(s->bytes * 8/(1024*1024))/(double)(o_interval_ms/1000));
	write(fd, buf, strlen(buf));
	close(fd);

	rename(filename, filename_stats);
	chmod(filename_stats, 0644);
	remove(filename);

	return 0;
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	(void)user;
	(void)h;
	(void)bytes;

	stats.bytes += h->len;
}



int main(int argc, char** argv)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	//struct pcap_pkthdr header;	/* The header that pcap gives us */
	//const u_char *packet;		/* The actual packet */
	struct timeval t1, t2;
	double elapsedTime;

	(void)argc;
	(void)argv;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
			return 2;
	}

	if (pcap_setnonblock(handle, 1, errbuf)) {
		fprintf(stderr, "Couldn't set non-blocking %s: %s\n", dev, errbuf);
		return 2;
	}

	//gettimeofday(&t1, NULL);
	while (1) {
		int n;
		n = pcap_dispatch(handle, 0, pcap_callback, NULL);
		(void)n;
		//packet = pcap_next(handle, &header);
		//(void)packet;


		//stats.bytes += header.len;
		gettimeofday(&t2, NULL);

		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
    	elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms

		if (elapsedTime >= o_interval_ms) {

			if (o_dump_stats) {
				dump_statistic(&stats);
			}
			dump_statistic_to_file("/tmp/statistic", &stats);

			memset(&stats, 0, sizeof(struct statistic));
			gettimeofday(&t1, NULL);
		}
	}

	pcap_close(handle);

	return 0;
}
