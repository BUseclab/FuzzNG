#ifndef CONVEYOR_H
#define CONVEYOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

void ic_setup(size_t max_input);
void ic_new_input(uint8_t* in, size_t len);
void ic_output(uint8_t *out, size_t *len, size_t max_len);
int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max);
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max);
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max, uint32_t mask);
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max);
uint8_t* ic_ingest_buf(size_t *len, uint8_t* token, size_t token_len, int minlen, int string);
void *ic_advance_until_token(uint8_t* token, size_t len);
size_t ic_get_last_token(void);
void* ic_insert(void* src, size_t len, size_t pos);
size_t ic_length_until_token(uint8_t* token, size_t len);
void ic_erase_backwards_until_token(void);
size_t ic_get_cursor(void);

// Returns the size of the next buffer
size_t ic_lookahead(uint8_t* token, size_t token_len) ;
#endif
