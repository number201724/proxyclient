#include "defs.h"
#include "ringbuffer.h"

ringbuffer::ringbuffer()
{
	_cursize = 0;
	_wpos = 0;
	_rpos = 0;
}

bool ringbuffer::front(void *data, size_t len)
{
	size_t lastlen = len;
	size_t tmplen;
	unsigned char *dst;
	size_t rpos;
	size_t cursize;

	if (_cursize < len)
		return false;

	cursize = _cursize;
	rpos = _rpos;
	dst = (unsigned char *)data;
	do
	{
		tmplen = (FRAGMENT_LEN - rpos);

		if (tmplen > lastlen)
		{
			memcpy(&dst[len - lastlen], &_ram[rpos], lastlen);
			rpos += lastlen;
			cursize -= lastlen;
			return true;
		}
		else
		{
			memcpy(&dst[len - lastlen], &_ram[rpos], tmplen);
			lastlen -= tmplen;
			rpos = 0;
			cursize -= tmplen;
		}
	} while (lastlen > 0);

	return true;
}

void ringbuffer::pop(size_t len)
{
	size_t lastlen = len;
	size_t tmplen;

	if (_cursize < len)
	{
		
		return;
	}

	do
	{
		tmplen = (FRAGMENT_LEN - _rpos);
		
		if (tmplen > lastlen)
		{
			_rpos += lastlen;
			_cursize -= lastlen;
			break;
		}
		else
		{
			lastlen -= tmplen;
			_rpos = 0;
			_cursize -= tmplen;
		}

	} while (lastlen > 0);
}

bool ringbuffer::deque(void *data, size_t len)
{
	size_t lastlen = len;
	size_t tmplen;
	unsigned char *dst;

	if (_cursize < len)
		return false;

	dst = (unsigned char *)data;
	do
	{
		tmplen = (FRAGMENT_LEN - _rpos);

		if (tmplen > lastlen)
		{
			memcpy(&dst[len - lastlen], &_ram[_rpos], lastlen);
			_rpos += lastlen;
			_cursize -= lastlen;
			return true;
		}
		else
		{
			memcpy(&dst[len - lastlen], &_ram[_rpos], tmplen);
			lastlen -= tmplen;
			_rpos = 0;
			_cursize -= tmplen;
		}

	} while (lastlen > 0);

	return true;
}

bool ringbuffer::queue(const void *data, size_t len)
{
	const unsigned char *indata;
	size_t copylen;
	size_t newlen = (len + _cursize);

	indata = (unsigned char *)data;

	//OVERFLOW CHECK
	if (newlen > sizeof(_ram))
	{
		return false;
	}

	copylen = 0;

	do
	{
		size_t endsize = (FRAGMENT_LEN - _wpos);

		if (endsize > (len - copylen))
		{
			memcpy(&_ram[_wpos], &indata[copylen], len - copylen);
			_wpos += (len - copylen);
			_cursize += (len - copylen);
			return true;
		}
		else
		{
			memcpy(&_ram[_wpos], &indata[copylen], endsize);
			_cursize += endsize;
			_wpos = 0;
			copylen += endsize;
		}
	} while ((len - copylen) > 0);

	return true;
}

void ringbuffer::clear()
{
	_cursize = 0;
	_wpos = 0;
	_rpos = 0;
}

size_t ringbuffer::size()
{
	return _cursize;
}

bool ringbuffer::empty()
{
	return _cursize == 0;
}