// SPDX-License-Identifier: Apache-2.0
/*
 * Independent structural C reader for the shared kernel-plan golden corpus.
 * This checks cross-language framing, bounds, and offsets only. It is not a
 * semantic admission decoder and must never be promoted into a privileged
 * worker without independently validating every policy and digest cross-link.
 */

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aos-sandbox-network-kernel-plan.h"

static uint8_t golden[AOS_NETWORK_KERNEL_PLAN_MAX_BYTES + 1];
static uint8_t mutated[AOS_NETWORK_KERNEL_PLAN_MAX_BYTES + 1];

static uint16_t read_be16(const uint8_t *bytes)
{
  return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | bytes[3];
}

static int all_zero(const uint8_t *bytes, size_t length)
{
  for (size_t index = 0; index < length; index++) {
    if (bytes[index] != 0)
      return 0;
  }
  return 1;
}

static int checked_advance(size_t *cursor, size_t count, size_t width,
                           size_t length)
{
  if (count != 0 && width > SIZE_MAX / count)
    return -1;
  size_t bytes = count * width;
  if (*cursor > length || bytes > length - *cursor)
    return -1;
  *cursor += bytes;
  return 0;
}

static int validate_plan(const uint8_t *bytes, size_t length)
{
  static const uint8_t magic[8] = {'A', 'O', 'S', 'N', 'K', 'P', '0', '1'};
  size_t cursor = AOS_NETWORK_KERNEL_PLAN_FIXED_BYTES;
  uint16_t address_pairs;
  uint16_t routes;
  uint16_t endpoints;

  if (length < AOS_NETWORK_KERNEL_PLAN_FIXED_BYTES ||
      length > AOS_NETWORK_KERNEL_PLAN_MAX_BYTES ||
      memcmp(bytes, magic, sizeof(magic)) != 0 ||
      read_be16(bytes + 8) != AOS_NETWORK_KERNEL_PLAN_VERSION ||
      bytes[10] != AOS_NETWORK_KERNEL_ACTION_PREPARE ||
      bytes[11] !=
          AOS_NETWORK_NAMESPACE_PUBLICATION_RETAINED_DESCRIPTOR_TARGET ||
      read_be32(bytes + 12) != length || bytes[136] < 1 ||
      bytes[136] > 4 || bytes[137] > 1 || bytes[138] > 1 ||
      bytes[139] != 0 || !all_zero(bytes + 188, 4) ||
      !all_zero(bytes + 390, 2))
    return -1;

  address_pairs = read_be16(bytes + 384);
  routes = read_be16(bytes + 386);
  endpoints = read_be16(bytes + 388);
  if (address_pairs > AOS_NETWORK_KERNEL_PLAN_MAX_ADDRESS_PAIRS ||
      routes > AOS_NETWORK_KERNEL_PLAN_MAX_ROUTES ||
      endpoints > AOS_NETWORK_KERNEL_PLAN_MAX_ENDPOINTS ||
      checked_advance(&cursor, address_pairs,
                      AOS_NETWORK_KERNEL_PLAN_ADDRESS_PAIR_BYTES, length) != 0 ||
      checked_advance(&cursor, routes, AOS_NETWORK_KERNEL_PLAN_ROUTE_BYTES,
                      length) != 0)
    return -1;

  for (uint16_t endpoint = 0; endpoint < endpoints; endpoint++) {
    uint16_t flows;

    if (checked_advance(&cursor, 1, AOS_NETWORK_KERNEL_PLAN_ENDPOINT_BYTES,
                        length) != 0)
      return -1;
    flows = read_be16(bytes + cursor - AOS_NETWORK_KERNEL_PLAN_ENDPOINT_BYTES +
                      16);
    if (flows == 0 || flows > AOS_NETWORK_KERNEL_PLAN_MAX_FLOWS_PER_ENDPOINT ||
        checked_advance(&cursor, flows, AOS_NETWORK_KERNEL_PLAN_FLOW_BYTES,
                        length) != 0)
      return -1;
  }

  return cursor == length ? 0 : -1;
}

static int hex_nibble(int character)
{
  if (character >= '0' && character <= '9')
    return character - '0';
  if (character >= 'a' && character <= 'f')
    return character - 'a' + 10;
  if (character >= 'A' && character <= 'F')
    return character - 'A' + 10;
  return -1;
}

static int read_hex(const char *path, uint8_t *bytes, size_t *length)
{
  FILE *file = fopen(path, "r");
  int high = -1;
  int character;

  if (file == NULL)
    return -1;
  *length = 0;
  while ((character = fgetc(file)) != EOF) {
    int nibble;

    if (character == '#') {
      while ((character = fgetc(file)) != EOF && character != '\n')
        ;
      continue;
    }
    if (isspace((unsigned char)character))
      continue;
    nibble = hex_nibble(character);
    if (nibble < 0 || *length >= AOS_NETWORK_KERNEL_PLAN_MAX_BYTES) {
      fclose(file);
      return -1;
    }
    if (high < 0) {
      high = nibble;
    } else {
      bytes[(*length)++] = (uint8_t)((high << 4) | nibble);
      high = -1;
    }
  }
  if (ferror(file) || fclose(file) != 0 || high >= 0)
    return -1;
  return 0;
}

static int parse_hex_byte(const char *text, uint8_t *value)
{
  int high;
  int low;

  if (strlen(text) != 2)
    return -1;
  high = hex_nibble((unsigned char)text[0]);
  low = hex_nibble((unsigned char)text[1]);
  if (high < 0 || low < 0)
    return -1;
  *value = (uint8_t)((high << 4) | low);
  return 0;
}

static int check_mutation_corpus(const char *path, size_t golden_length)
{
  FILE *file = fopen(path, "r");
  char line[256];
  unsigned int cases = 0;

  if (file == NULL)
    return -1;
  while (fgets(line, sizeof(line), file) != NULL) {
    char label[32];
    char operation[16];
    char value_text[8];
    unsigned long offset;
    uint8_t value;
    size_t length = golden_length;

    if (line[0] == '#' || isspace((unsigned char)line[0]))
      continue;
    memcpy(mutated, golden, golden_length);
    if (sscanf(line, "%31s %15s %lu %7s", label, operation, &offset,
               value_text) == 4 && strcmp(operation, "replace") == 0) {
      size_t text_length = strlen(value_text);

      if (text_length == 0 || (text_length & 1) != 0 || offset > length ||
          text_length / 2 > length - offset)
        goto fail;
      for (size_t index = 0; index < text_length / 2; index++) {
        char pair[3] = {value_text[index * 2], value_text[index * 2 + 1], 0};

        if (parse_hex_byte(pair, &mutated[offset + index]) != 0)
          goto fail;
      }
    } else if (sscanf(line, "%31s %15s %7s", label, operation,
                      value_text) == 3 && strcmp(operation, "append") == 0) {
      if (length >= AOS_NETWORK_KERNEL_PLAN_MAX_BYTES ||
          parse_hex_byte(value_text, &value) != 0)
        goto fail;
      mutated[length++] = value;
    } else {
      goto fail;
    }
    if (validate_plan(mutated, length) == 0) {
      fprintf(stderr, "mutation unexpectedly valid: %s\n", label);
      goto fail;
    }
    cases++;
  }
  if (ferror(file) || fclose(file) != 0 || cases != 3)
    return -1;
  return 0;

fail:
  fclose(file);
  return -1;
}

static int check_known_vector(const uint8_t *bytes, size_t length)
{
  static const uint8_t host_name[16] = "aoh000000000001";
  static const uint8_t sandbox_name[16] = "aog000000000001";

  return length == 544 && read_be32(bytes + 12) == 544 &&
                 bytes[136] == 4 && bytes[137] == 1 && bytes[138] == 1 &&
                 read_be32(bytes + 140) == 1500 &&
                 memcmp(bytes + 144, host_name, sizeof(host_name)) == 0 &&
                 memcmp(bytes + 160, sandbox_name, sizeof(sandbox_name)) == 0 &&
                 read_be16(bytes + 384) == 1 &&
                 read_be16(bytes + 386) == 1 &&
                 read_be16(bytes + 388) == 1 && bytes[392] == 4 &&
                 bytes[393] == 31 && bytes[428] == 4 && bytes[429] == 24 &&
                 read_be16(bytes + 480) == 1 && bytes[516] == 1 &&
                 bytes[517] == 1 && bytes[518] == 4 && bytes[519] == 24 &&
                 read_be16(bytes + 536) == 443 &&
                 read_be16(bytes + 538) == 443 && bytes[540] == 1
             ? 0
             : -1;
}

int main(int argc, char **argv)
{
  size_t length;

  if (argc != 3) {
    fprintf(stderr, "usage: network-kernel-plan-codec GOLDEN CASES\n");
    return 2;
  }
  if (read_hex(argv[1], golden, &length) != 0 ||
      validate_plan(golden, length) != 0 ||
      check_known_vector(golden, length) != 0 ||
      check_mutation_corpus(argv[2], length) != 0) {
    fprintf(stderr, "Network kernel-plan C conformance failed: %s\n",
            strerror(errno));
    return 1;
  }
  puts("PASS network-kernel-plan-codec-v1");
  return 0;
}
