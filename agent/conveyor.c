#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "conveyor.h"
#include <x86intrin.h>
#include <stdio.h>
#include "fuzz.h"


static uint8_t *input;
static uint8_t *input_cursor;
static size_t input_len;

static uint8_t *output;
static uint8_t *output_cursor;
static size_t *output_len;

static uint8_t *last_token;
static size_t bufsize;


static uint8_t *zeros;

void ic_setup(size_t max_input){
    output = malloc(max_input);
    zeros = calloc(1, max_input);
    bufsize = max_input;
}

// Ingest a new input
void ic_new_input(uint8_t* in, size_t len) {
    input = in;
    input_cursor = input;
    input_len = len;

    assert(output);
    output_cursor = output;
    *output_len = 0;
    last_token = output;
}

size_t ic_get_cursor(void){
    return output_cursor - output;
}
size_t ic_get_last_token(void){
    return last_token-output;
}

size_t ic_lookahead(uint8_t* token, size_t token_len) { 
    size_t ret = 0;
    uint8_t *next_token = memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            token_len);
    if(!next_token || next_token+token_len >= input+input_len)
        return ret;
    uint8_t *after_next_token = memmem(next_token+token_len,
            input + input_len - next_token - token_len,
            token,
            token_len);
    if(!after_next_token)
        return (input+input_len-next_token-token_len);
    return after_next_token - next_token - token_len;
}

static inline void* append(void* src, size_t len){
    if(!(output_cursor && output_cursor - output + len < bufsize)){
        debug_printf("append: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        abort_input();
    }
    memcpy(output_cursor, src, len);
    output_cursor += len;
    *output_len = output_cursor - output;
    return output_cursor;
}

void* ic_insert(void* src, size_t len, size_t pos){
    if(!(output_cursor && output_cursor - output + len < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        abort_input();
    }
    if(!((output_cursor - output) + len < bufsize) ) {
        debug_printf("ic_insert: %s", "Assert: ((output_cursor - output) + len < bufsize)\n");
        abort_input();
    }
    if(!(pos < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (pos < bufsize)\n");
        abort_input();
    }
    memmove(output+pos+len, output+pos, len);
    memcpy(output+pos, src, len);
    output_cursor += len;
    *output_len = output_cursor - output;
    return output_cursor;
}

static inline void* size_ptr(size_t len){
    if (input_cursor + len > input + input_len)
        return NULL;
    input_cursor += len;
    return input_cursor - len;
}

// Return a "cannonical input": one with extraneous bytes removed, and missing
// bytes inserted (where needed).
void ic_output(uint8_t *out, size_t *len, size_t max_len)
{
    output = out;
    output_len = len;
}

int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max) {
    void *src = size_ptr(sizeof(uint8_t));
    assert(max > min);
    if(src){
        memcpy(result, src, sizeof(uint8_t));
        *result = min + ((*result - min) % (max - min));
        append(result, sizeof(uint8_t));
        return 0;
    }
    return -1;
}
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max) {
    void *src = size_ptr(sizeof(*result));
    assert(max > min);
    if(src){
        memcpy(result, src, sizeof(*result));
        *result = min + ((*result - min) % (max - min));
        append(result, sizeof(*result));
        return 0;
    }
    return -1;
}
int ic_ingest32(uint32_t *result,uint32_t min, uint32_t max, uint32_t mask) {

    void *src = size_ptr(sizeof(*result));
    assert(max > min);
    if(src){
        memcpy(result, src, sizeof(*result));
        //*result = min + ((*result - min) % (max - min));
        *result = (*result) & mask;
        append(result, sizeof(*result));
        return 0;
    }
    return -1;
}

int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max) {

    void *src = size_ptr(sizeof(*result));
    assert(max > min);
    if(src){
        memcpy(result, src, sizeof(*result));
        *result = min + ((*result - min) % (max - min));
        append(result, sizeof(*result));
        return 0;
    }
    return -1;
}

uint8_t* ic_ingest_buf(size_t *len, uint8_t* token, size_t token_len, int minlen, int string) {
    debug_printf("INGEST: %ld %d. CURSOR: %p INPUT_END: %p\n", *len, minlen, input_cursor, input+input_len);
    uint8_t *result = output_cursor;
    uint8_t *token_position;
    size_t maxlen, until_token_len;
    maxlen = *len;
    size_t remaining_len = maxlen;
    size_t filled = 0;

    token_position = memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            token_len);
    debug_printf("TOKEN_POSITION: %lx (%p)\n", token_position - input_cursor, token_position);
    if(token_position && token_position - input_cursor < maxlen) {
        until_token_len = token_position - input_cursor;
    } else if(token_position) {
        until_token_len = maxlen;
    } else if(input+input_len-input_cursor > maxlen) {
        until_token_len = maxlen;
    } else {
        until_token_len = input+input_len-input_cursor;
    }
    
    debug_printf("UNTIL_TOKEN_LEN: %ld\n", until_token_len);
    // First try to read data from the actual buffer (until token)
    uint8_t* ret = size_ptr(until_token_len);
    if(ret) { 
        append(ret, until_token_len);
        filled += until_token_len;
        remaining_len -= until_token_len;
    }

    // Next, fill the rest with random data.
    // Cap the total len at minlen
    if(minlen != -1 && remaining_len + filled > minlen) {
        if(minlen > filled)
            remaining_len = minlen - filled;
        else 
            remaining_len = 0;
    }
    srand(__rdtsc());
    memset(zeros, 0, remaining_len);

    if(string) { // Fill it with random ascii
        for(int i=0; i<remaining_len && remaining_len; i++){
            zeros[i] = 0x32 + (rand()%(0x7e - 0x32));
        }
        if(remaining_len){
            zeros[remaining_len-1] = '\x00';
        }
    } else {
        for(int i=0; i<(rand()%8)*remaining_len/16 && remaining_len; i++) {
            zeros[rand()%remaining_len] = rand()&0xFF;
        }
    }

    if(!append(zeros, remaining_len)) {
            return NULL;
    }
    else {
        filled += remaining_len;
    }
    *len = filled;
    debug_printf("INGEST RESULT: %ld @%p\n", *len, result);
    return result;
}

void *ic_advance_until_token(uint8_t* token, size_t len) {
    uint8_t* token_position = memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            len);
    if (token_position) {
        last_token = append(token, len) - len;
        input_cursor = token_position + len;
    }
    return token_position;
}

size_t ic_length_until_token(uint8_t* token, size_t len) {
    uint8_t* token_position = memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            len);
    if (token_position) {
        return token_position-input_cursor;
    }
    return -1;
}

// Erase until the last token 
void ic_erase_backwards_until_token(void) {
    if(last_token) {
        output_cursor = last_token;
        *output_len = output_cursor - output;
    }
}
