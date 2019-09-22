#pragma once

#define FRAGMENT_LEN 1024

class ringbuffer
{
public:
	ringbuffer();
	bool front(void *data, size_t len);
	void pop(size_t len);
	bool deque(void *data, size_t len);
	bool queue(const void *data, size_t len);
	void clear();
	size_t size();
	bool empty();

private:
	size_t _cursize;
	size_t _wpos;
	size_t _rpos;
	unsigned char _ram[FRAGMENT_LEN];
};