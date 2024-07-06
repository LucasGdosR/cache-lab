#define _GNU_SOURCE
#include "cachelab.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int valid;
    size_t tag;
} Line;

typedef struct {
    int lru_line;
    Line *lines;
} Set;

typedef struct {
    int set_count;
    int line_count;
    Set *sets;
} Cache;

void init_cache(Cache *cache, int set_bits, int lines_per_set) {
    int set_count = 1 << set_bits;
    cache->set_count = set_count;
    cache->line_count = lines_per_set;
    cache->sets = (Set *) malloc(set_count * sizeof(Set));
    if (cache->sets == NULL) {
        fprintf(stderr, "Error: malloc for cache->sets.\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < set_count; i++) {
        Set *set = &cache->sets[i];
        set->lru_line = 0;
        set->lines = (Line *) malloc(lines_per_set * sizeof(Line));
        if (set->lines == NULL) {
            fprintf(stderr, "Error: malloc for set->lines.\n");
            exit(EXIT_FAILURE);
        } for (int j = 0; j < lines_per_set; j++) set->lines[j].valid = 0;
    }
}

void free_cache(Cache *cache) {
    int set_count = cache->set_count;
    for (int i = 0; i < set_count; i++) {
        free(cache->sets[i].lines);
    }
    free(cache->sets);
}

int get_set_index(size_t address, int set_count, int b) {
    return (address >> b) % set_count;
}

size_t get_tag_bits(size_t address, size_t tag_mask, int tag_shift) {
    return (address >> tag_shift) & tag_mask;
}

int line_has_address(size_t tag_bits, Line *line) {
    return line->valid && (line->tag == tag_bits);
}

int main(int argc, char *argv[])
{
    int opt, verbose = 0, s = -1, E = -1, b = -1;
    char *tracefile = NULL;

    while ((opt = getopt(argc, argv, "hvs:E:b:t:")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s [-hv] -s <s> -E <E> -b <b> -t <tracefile>\n", argv[0]);
                exit(EXIT_SUCCESS);
            case 'v':
                verbose++;
                break;
            case 's':
                s = atoi(optarg);
                break;
            case 'E':
                E = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 't':
                tracefile = optarg;
                break;
            default:
                fprintf(stderr, "Invalid option or missing argument.\n");
                exit(EXIT_FAILURE);
        }
    }

    if (s < 0 || E < 1 || b < 0 || tracefile == NULL) {
        fprintf(stderr, "Missing required arguments.\n");
        exit(EXIT_FAILURE);
    }

    FILE *fp = fopen(tracefile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file.\n");
        exit(EXIT_FAILURE);
    }

    Cache cache;
    init_cache(&cache, s, E);
    int tag_shift = s + b;
    size_t tag_mask = (1UL << (64 - tag_shift)) - 1UL;
    
    char *buffer = NULL;
    size_t n = 0;
    ssize_t nread;
    long hits = 0, misses = 0, evictions = 0;
    while ((nread = getline(&buffer, &n, fp)) != -1) {
        if (nread <= 1 || buffer[0] == 'I') continue;
        int op_is_M = buffer[1] == 'M';
        hits += op_is_M;

        buffer[strlen(buffer) - 1] = '\0';
        if (verbose) printf("%s", buffer + 1);

        char *address_str = buffer + 3;
        size_t address = strtoul(address_str, NULL, 16);

        int set_index = get_set_index(address, cache.set_count, b);
        Set *set = &cache.sets[set_index];

        int lru_line = set->lru_line;
        Line *lines = set->lines;
        size_t tag_bits = get_tag_bits(address, tag_mask, tag_shift);
        int hit = 0;
        for (int i = 0; i < E; i++) {
            Line *line = &lines[(i + lru_line) % E];
            if (line_has_address(tag_bits, line)) {
                if (verbose) printf(" hit%s\n", op_is_M ? " hit" : "");
                hits++;
                hit = 1;
                while (i < E - 1) {
                    int index = i + lru_line;
                    lines[index % E] = lines[(index + 1) % E];
                    i++;
                }
                int index = lru_line == 0 ? (E - 1) : (lru_line - 1);
                lines[index].tag = tag_bits;
            }
        }
        
        if (!hit) {
            misses++;
            Line *line = &lines[set->lru_line++];
            set->lru_line %= E;
            if (verbose) printf(" miss%s%s\n", line->valid ? " eviction" : "", op_is_M ? " hit" : "");
            line->tag = tag_bits;
            if (!(line->valid)) line->valid = 1;
            else evictions++;
        }
    }

    fclose(fp);
    free(buffer);
    free_cache(&cache);
    
    printSummary(hits, misses, evictions);
    return 0;
}
