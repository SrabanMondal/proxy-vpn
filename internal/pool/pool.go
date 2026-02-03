package pool

import "sync"

const (
    MaxPacketSize = 1500
)

var bytePool = sync.Pool{
    New: func() any {
        return make([]byte, MaxPacketSize)
    },
}

// Get borrows a buffer from the pool
func Get() []byte {
    return bytePool.Get().([]byte)
}

// Put returns a buffer to the pool. 
func Put(b []byte) {
    bytePool.Put(b[:cap(b)])
}