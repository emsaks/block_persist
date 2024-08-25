#include <linux/bio.h>
#include "blockthru.h"

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

	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;
	struct bt_dev * bt = stash->disk->bt;

	if (bt->salvaged_bytes < 0 || bio->bi_opf != REQ_OP_READ)
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

	struct bio_stash * stash = (struct bio_stash*)bio->bi_private;
	struct bt_dev * bt = stash->disk->bt;

	if (bt->salvaged_bytes < 0 || bio->bi_opf != REQ_OP_READ)
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
			pw("Salvage: Bug? Final sector was modified even though bio has error");
		} else {
			pw("Salvaged %zi bytes.\n", salvaged);
			bt->salvaged_bytes += salvaged;
		}
	}

	return salvaged;
}

DEVICE_ATTR_LONG_RW(salvaged_bytes, dev_to_bt(dev));