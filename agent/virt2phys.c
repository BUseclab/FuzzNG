#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PAGEMAP_LENGTH              8

size_t virt_to_phys(void* vaddr){
        unsigned long paddr = 0;
        int page_size, page_shift = -1;
        FILE *pagemap = fopen("/proc/self/pagemap", "rb");
        page_size = sysconf(_SC_PAGESIZE);
        size_t offset = ((size_t)vaddr / page_size) * PAGEMAP_LENGTH;
        fseek(pagemap, (unsigned long)offset, SEEK_SET);
        if (fread(&paddr, 1, (PAGEMAP_LENGTH-1), pagemap) < (PAGEMAP_LENGTH-1)) {
                perror("fread fails. ");
                exit(0);
        }
        paddr = paddr & 0x7fffffffffffff;
        /* printf("physical frame address is 0x%lx\n", paddr); */

        offset = (size_t)vaddr % page_size;

        /* PAGE_SIZE = 1U << PAGE_SHIFT */
        while (!((1UL << ++page_shift) & page_size));

        paddr = (unsigned long)((unsigned long)paddr << page_shift) + offset;
        //printf("physical address is 0x%lx\n", paddr);
        fclose(pagemap);
        return paddr;
}
