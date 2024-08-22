#include <linux/bio.h>
#include "blockthru.h"

unsigned long total_salvaged_bytes = 0;

struct {
	char magic[17];
	void * page;
	int off;
} magic = {{'B','l','o','c','k','t','h','r','u',' ','s','a','l','v','a','g','e'}};

void prep_bio(struct bio * bio)
{
	void * mem;
	struct bio_vec bvec;
	struct bvec_iter iter;

	if (bio->bi_opf != REQ_OP_READ)
		return;

	bio_for_each_segment(bvec, bio, iter) {
		magic.page = bvec.bv_page;
		mem = bvec_kmap_local(&bvec);
		for (magic.off = 0; magic.off < bvec.bv_len; magic.off += 512) {
			memcpy(mem+magic.off, &magic, sizeof(magic));
		}

		kunmap_local(mem);
	}
	
}

size_t salvage_bio(struct bio * bio)
{
	size_t salvaged = 0;
	int in_error = 1;
	int salvaged_segments = 0;

	void * mem;
	struct bio_vec bvec;
	struct bvec_iter iter;
	
	if (bio->bi_opf != REQ_OP_READ)
		return 0;

	bio_for_each_segment(bvec, bio, iter) {
		magic.page = bvec.bv_page;
		mem = bvec_kmap_local(&bvec);
		for (magic.off = 0; magic.off < bvec.bv_len; magic.off += 512) {
			if (memcmp(mem, &magic, sizeof(magic))) {
				salvaged += 512;
				if (in_error) {
					in_error = 0;
					++salvaged_segments;
				}
			} else {
				in_error = 1;
			}
		}

		kunmap_local(mem);
	}

	if (salvaged) {
		pr_warn("Salvaged %zu bytes in %i segments.\n", salvaged, salvaged_segments);
	}

	total_salvaged_bytes += salvaged;
	return salvaged;
}

static ssize_t salvaged_bytes_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", total_salvaged_bytes);
}
DEVICE_ATTR_RO(salvaged_bytes);