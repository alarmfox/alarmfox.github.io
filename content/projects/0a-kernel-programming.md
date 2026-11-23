+++
date = '2026-11-15T11:13:46+01:00'
author = "alarmfox"
draft = true
title = '[Part 0a - Work in Progress] (A)KP: Caches and memory coherence'
keywords = ["advanced", "kernel", "programming", "os", "computer", "architecture"]
+++

# Introduction

In this post, we are diving into cache systems and memory coherence.

This is part of a bigger series.

## Cache systems

### What is a cache?

A cache is a type of memory. In this context, caches are supposed to be very fast since they are typically built with SRAM techonology (we don't deep dive into that here).

A cache is organized in **lines** or **blocks** which has a fixed size (defined by construction; eg. 128 bytes) with some metadata associated to it.

For SRAM things, cache is small and is not organized as main memory. How does a cache work? We access some data given an address (it can be data or instruction). If the data is in cache, we can just take it from cache (Cache HIT). Otherwise, we need to ask the data from the main memory (Cache MISS; every miss we pay the cost of accessing slower memory). When we need to store data, we need to choose a policy based on our *consistency* protocol. What happens when we store the data and the cache already contains data? Since cache is small there will be some sort of conflicts where same addresses share the same places. There must be a way to **evict** a line.

> Consistency? For example, do we always keep memory updated? What if different element are communicating using a variable and they just write things in their cache? They would never communicate since they are using different version of the same variable

> Consistency is a thing we focus in next episode

Historically, there are different kind of cache architectures.

Too much yapping, let's introduce some code. We will try to explain with `C` code how a cache works. We suppose the existence of functions:

```c
extern void slow_memory_access_read(...);
extern void slow_memory_access_write(...);
```

We will suppose 64-bit addresses and the cache byte-addressable. The code can be extended to get more bytes at once.

#### Direct cache
We just treat the cache as an array. For example, given a cache with `N` rows, we compute `address % N` and obtain the slot. If it is a read, we just use HIT/MISS, if there is a write we just need to evict the line and save it in memory before.

First, we need address partitioning. What if 2 addresses fit in the same slot but they are different? We use part of the address for different part of the algorithm. The figure below shows how we common divide the address. Depending on how many cache lines we have, we choose the number of bits to represent the index and based on how big the cache line is we choose the number of bits for the offset.

```bob
64-bit address
16 rows -> 4 bits
64-bit cache lines -> 6 bits
54-bit tag

  4-bit   64 - (4+6) = 54-bit    6-bit
+----------------------------------------+
| index |         tag        |  offset   |
+----------------------------------------+
```

In this case, we model the cache line with a simple structure. We need to know if an entry is valid or not.

```c
struct dm_cache_entry {
    uint8_t valid;
    uint64_t tag;
    uint8_t data[DM_CACHE_BLOCK_SIZE];
};

static struct dm_cache_entry dm_cache[DM_CACHE_LINES];
```

Some definitions:

```c
/* Direct mapped cache */
#define DM_CACHE_SIZE           1024
#define DM_CACHE_BLOCK_SIZE     64
#define DM_CACHE_LINES          DM_CACHE_SIZE / DM_CACHE_BLOCK_SIZE

#define DM_CACHE_TAG_BITS      54
#define DM_CACHE_INDEX_BITS    4
#define DM_CACHE_OFFSET_BITS   6

#define DM_CACHE_OFFSET_MASK  ((1UL << DM_CACHE_OFFSET_BITS) - 1)
#define DM_CACHE_INDEX_MASK   (((1UL << DM_CACHE_INDEX_BITS) - 1) << DM_CACHE_OFFSET_BITS)
#define DM_CACHE_TAG_MASK   (((1UL << DM_CACHE_TAG_BITS) - 1) << (DM_CACHE_INDEX_BITS + DM_CACHE_OFFSET_BITS))
```

Define the `dm_lookup`. We just need to compute the slot from the address and retrieve data if present otherwise we issue the `slow_memory_access` function.
First, we compute index, tag and offset with simple bit manipulation. We get the entry. If the tag of the stored cache line correnspond to our tag, we return the data. Otherwise we just fetch data from memory and store it in the cache entry.

```c
static uint8_t dm_lookup(const struct dm_cache_entry *cache, uintptr_t address) {
    uintptr_t aligned = address & ~(DM_CACHE_BLOCK_SIZE - 1);

    uint64_t index = ((aligned & DM_CACHE_INDEX_MASK) >> DM_CACHE_OFFSET_BITS) % DM_CACHE_LINES;
    uint64_t tag = (aligned & DM_CACHE_TAG_MASK) >> (DM_CACHE_INDEX_BITS + DM_CACHE_OFFSET_BITS);
    uint64_t offset = (address & DM_CACHE_OFFSET_MASK);

    /* Get cache entry */
    struct dm_cache_entry *entry = &cache->entries[index];

    /* Cache hit */
    if(entry->valid && tag == entry->tag) {
        return entry->data[offset];
    }

    /* Out of bound */
    if(aligned + DM_CACHE_BLOCK_SIZE > MEMORY_SIZE) {
        return 0;
    }

    /* Cache miss: fetch data from memory */
    slow_memory_access_read(entry->data, DM_CACHE_BLOCK_SIZE);

    entry->valid = 1;
    entry->tag = tag;

    return entry->data[offset];;
}
```

Same thing for storing data. In this simple case, we adopt the write through policy. So we must update also memory to keep it consistent.

```c

/* Perform write through: always update the memory */
static void dm_write_through(struct dm_cache *cache, uintptr_t address, uint8_t data) {
    uintptr_t aligned = address & ~(DM_CACHE_BLOCK_SIZE - 1);
    uint64_t index = ((aligned & DM_CACHE_INDEX_MASK) >> DM_CACHE_OFFSET_BITS) % DM_CACHE_LINES;
    uint64_t tag = (aligned & DM_CACHE_TAG_MASK) >> (DM_CACHE_INDEX_BITS + DM_CACHE_OFFSET_BITS);
    uint64_t offset = (aligned & DM_CACHE_OFFSET_MASK);

    struct dm_cache_entry *entry = &cache->entries[index];

    if(address + offset >= MEMORY_SIZE) return;

    /* Always update memory */
    slow_memory_access_write(data, DM_CACHE_BLOCK_SIZE);

    /* load on write: Load block on miss */
    if(!entry->valid || tag != entry->tag) {
        entry->valid = 1;
        entry->tag = tag;
        slow_memory_access_read(entry->data, DM_CACHE_BLOCK_SIZE);
    }
    entry->data[offset] = data;
}

```

#### Set Associative

#### Current standard: K-Way Set associative

### General Idea
Cache is a whole subsystem itself. Cores' Load/Store (LS) unit are connected with L1 caches.
Typically, caches are organized in levels. Higher levels put more core together: L1 caches are per-core; L2 connects 2-4 cores; L3 connects all cores. However, we just need to think that there are `n` level of cache and the last level of cache (LLC) talks to the memory controller.

Let's understand why L1 caches are usually split in two Instruction cache (I-Cache) and Data cache (D-Cache). Let's recall our pipeline.

```bob


                                            +------------+
  Thread A                              +-->|    ALU     |---+
+-----------+                           |   |  add, and  |   |
| PC | regs |---+                       |   +------------+   |
+-----------+   |    +--------------+   |   +------------+   |    +------------+
                +--->| Fetch Decode |---+-->|  DIVIDER   |---+--->| Write back |
                     +--------------+   |   |    div     |   |    +------------+
                                        |   +------------+   |
+--------------+                        |   +------------+   |
|  Fetch Unit  |                        +-->| Load Store |---
+--------------+                            |    unit    |
                                            +------------+
+--------------+                         +-------------------+
|    I-Cache   |                         |      D-Cache      |
+--------------+                         +-------------------+
       |                                           |
       |                                           |
       +----------+                     +----------+
                  |                     |
                  |                     |
       +---------------------------------------------+
       |               Memory Controller             |
       +---------------------------------------------+
```

First, let's notice that they are in two different parts of our system. The most important reason is the access pattern. Let's think about **I-cache**. For the vast majority of time the PC is just incremented at every clock cycle. This is because program instructions are sequential in memory. Suppose we have the following program in memory:

```
# each instruction has a fixed length:  4-bytes (32-bit)
0xF000 => load.word a0, [0x1000]
0xF004 => load.word a1, [0x1004]
0xF008 => add a2, a1, a0
0xF00C => store.word [0x1008], a2
```

This program has no branches, no jumps, no function call. According to our pipeline, we would just need to fetch instruction one after the other. How can we exploit this "access pattern". The keyword here is **pre-fetch**. Memory connections can bridge more than 4-byte at a time. What if we fetch 10 instructions at time? Threat A fetches the instruction at `0xF000` and the fetch unit fetches asynchnoushly the next 4 instructions.
