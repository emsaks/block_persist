#include <linux/bio.h>
#include "blockthru.h"

size_t total_salvaged_bytes = 0;

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

	if (total_salvaged_bytes < 0 || bio->bi_opf != REQ_OP_READ)
		return;

	bio_for_each_segment(bvec, bio, iter) {
		magic.page = bvec.bv_page;
		mem = bvec_kmap_local(&bvec);
		for (magic.off = 0; magic.off < bvec.bv_len; magic.off += 512)
			memcpy(mem+magic.off, &magic, sizeof(magic));
		kunmap_local(mem);
	}
	
}

size_t salvage_bio(struct bio * bio)
{
	void * mem;
	struct bio_vec bvec;
	struct bvec_iter iter;
	size_t salvaged = 0;

	if (total_salvaged_bytes < 0 || bio->bi_opf != REQ_OP_READ)
		return 0;

	bio_for_each_segment(bvec, bio, iter) {
		magic.page = bvec.bv_page;

		mem = bvec_kmap_local(&bvec);
		for (magic.off = 0; magic.off < bvec.bv_len; magic.off += 512) {
			if (!memcmp(mem, &magic, sizeof(magic))) {
				magic.page = NULL;
				break;
			}
			salvaged += 512;
		}
		kunmap_local(mem);

		if (!magic.page)
			break;
	}

	if (salvaged) {
		if (magic.page) {
			pr_warn("Salvage: Bug? Final sector was modified even though bio has error");
		} else {
			pr_warn("Salvaged %zi bytes.\n", salvaged);
			total_salvaged_bytes += salvaged;
		}
	}

	return salvaged;
}

static ssize_t salvaged_bytes_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", total_salvaged_bytes);
}
static ssize_t salvaged_bytes_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	size_t v;

	err = kstrtol(buf, 10, &v);
	if (err || v > INT_MAX)
		return -EINVAL;

	total_salvaged_bytes = v;
	return count;
}
DEVICE_ATTR_RW(salvaged_bytes);