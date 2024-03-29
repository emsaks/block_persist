#include <linux/bio.h>

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

	if (op_is_write(bio->bi_opf))
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

	return salvaged;
}