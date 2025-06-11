#!/bin/bash

valgrind --tool=massif --stacks=yes ./hummingbird
OUT=$(ls -t massif.out.* | head -n1)

ms_print "$OUT" | awk '
  /^ / && NF == 6 {
    heap = $3 + $6
    if (heap > max) {
      max = heap
      heap_only = $3
      stack_only = $6
    }
  }
  END {
    printf "Peak total memory: %d B\n", max
    printf "  - Heap only:     %d B\n", heap_only
    printf "  - Stack only:    %d B\n", stack_only
  }'

