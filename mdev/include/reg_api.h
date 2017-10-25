#ifndef _REG_API_H
#define _REG_API_H
#include <stdio.h>
#include <stdint.h>

static inline uint8_t io_read8_relaxed(const volatile void *addr)
{
	return *(const volatile uint8_t *)addr;
}

static inline uint16_t io_read16_relaxed(const volatile void *addr)
{
	return *(const volatile uint16_t *)addr;
}

static inline uint32_t io_read32_relaxed(const volatile void *addr)
{
	return *(const volatile uint32_t *)addr;
}

static inline uint64_t io_read64_relaxed(const volatile void *addr)
{
	return *(const volatile uint64_t *)addr;
}

static inline void io_write8_relaxed(uint8_t value, volatile void *addr)
{
	*(volatile uint8_t *)addr = value;
}

static inline void io_write16_relaxed(uint16_t value, volatile void *addr)
{
	*(volatile uint16_t *)addr = value;
}

static inline void io_write32_relaxed(uint32_t value, volatile void *addr)
{
	*(volatile uint32_t *)addr = value;
}

static inline void io_write64_relaxed(uint64_t value, volatile void *addr)
{
	*(volatile uint64_t *)addr = value;
}

static inline uint8_t io_read8(const volatile void *addr)
{
	uint8_t val;
	val = io_read8_relaxed(addr);
	return val;
}

static inline uint16_t io_read16(const volatile void *addr)
{
	uint16_t val;
	val = io_read16_relaxed(addr);
	return val;
}

static inline uint32_t io_read32(const volatile void *addr)
{
	uint32_t val;
	val = io_read32_relaxed(addr);
	return val;
}

static inline uint64_t io_read64(const volatile void *addr)
{
	uint64_t val;
	val = io_read64_relaxed(addr);
	return val;
}

static inline void io_write8(uint8_t value, volatile void *addr)
{
	io_write8_relaxed(value, addr);
}

static inline void io_write16(uint16_t value, volatile void *addr)
{
	io_write16_relaxed(value, addr);
}

static inline void io_write32(uint32_t value, volatile void *addr)
{
	io_write32_relaxed(value, addr);
}

static inline void io_write64(uint64_t value, volatile void *addr)
{
	io_write64_relaxed(value, addr);
}

#endif
